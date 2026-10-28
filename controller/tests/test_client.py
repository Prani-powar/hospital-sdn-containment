"""Actual HTTP/async-client checks on a bounded local test server."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import unittest
from unittest.mock import patch

from controller.telemetry_client import ObservationCursor, TelemetryClient, request_json


class CursorTests(unittest.TestCase):
    @staticmethod
    def body(first=1, last=3, epoch="a", drops=0):
        return {"controller_epoch": epoch, "observation_last_seq": last,
                "observations": [{"seq": seq} for seq in range(first, last + 1)],
                "observation_guard_drops": {"source_guard_drops": drops,
                                           "global_guard_drops": 0}}

    def test_cursor_deduplicates_and_reports_missed_prefix_and_later_gap(self):
        cursor = ObservationCursor()
        result = cursor.read(self.body(first=3, last=5))
        self.assertEqual(result["missed_observations"], 2)
        self.assertFalse(result["continuity_ok"])
        self.assertEqual(cursor.read(self.body(first=3, last=5))["new_observations"], [])
        result = cursor.read(self.body(first=8, last=9))
        self.assertEqual(result["missed_observations"], 2)
        self.assertEqual([r["seq"] for r in result["new_observations"]], [8, 9])
        self.assertTrue(cursor.read(self.body(first=8, last=10))["continuity_ok"])

    def test_epoch_change_and_guard_deltas_are_explicit(self):
        cursor = ObservationCursor()
        cursor.read(self.body())
        result = cursor.read(self.body(last=4, drops=7))
        self.assertFalse(result["continuity_ok"])
        self.assertEqual(result["guard_drop_deltas"]["source_guard_drops"], 7)
        self.assertTrue(cursor.read(self.body(last=4, drops=7))["continuity_ok"])
        result = cursor.read(self.body(last=1, epoch="b"))
        self.assertTrue(result["epoch_changed"])
        self.assertFalse(result["continuity_ok"])

    def test_regression_rejected_without_advancing_cursor(self):
        cursor = ObservationCursor()
        cursor.read(self.body(drops=3))
        with self.assertRaises(ValueError):
            cursor.read(self.body(last=2, drops=3))
        with self.assertRaises(ValueError):
            cursor.read(self.body(last=4, drops=2))
        result = cursor.read(self.body(last=4, drops=3))
        self.assertEqual([r["seq"] for r in result["new_observations"]], [4])


class ClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                time.sleep(0.04)
                status = 200
                if self.path == "/v1/health":
                    status, body = 503, {"status": "degraded"}
                elif self.path == "/v1/stats":
                    body = {"complete": True, "switches": []}
                else:
                    body = {"schema_version": 1, "topology": {}}
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args: object) -> None:
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    async def test_real_reads_keep_asyncio_responsive_and_surface_degraded_health(self) -> None:
        client = TelemetryClient(self.base)
        ticks = 0
        async def heartbeat() -> None:
            nonlocal ticks
            for _ in range(4):
                ticks += 1
                await asyncio.sleep(0.01)
        stats, _, health = await asyncio.gather(client.get_stats(), heartbeat(), client.get_health())
        self.assertTrue(stats["complete"])
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(ticks, 4)
        self.assertEqual((await client.get_topology())["schema_version"], 1)

    async def test_stale_data_is_rejected_unless_explicitly_requested(self) -> None:
        client = TelemetryClient(self.base)
        with patch("controller.telemetry_client.request_json", return_value=(200, {"complete": False})):
            with self.assertRaises(RuntimeError):
                await client.get_stats()
            self.assertFalse((await client.get_stats(require_complete=False))["complete"])

    async def test_response_size_bound(self) -> None:
        with patch("controller.telemetry_client.MAX_RESPONSE_BYTES", 8):
            with self.assertRaises(ValueError):
                await asyncio.to_thread(request_json, self.base, "/v1/stats")

    async def test_disallow_external_endpoints_and_mutation_paths(self) -> None:
        for url in ("https://127.0.0.1:18080", "http://example.com",
                    "http://user:secret@127.0.0.1", "http://127.0.0.1/path"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                request_json(url, "/v1/stats")
        with self.assertRaises(ValueError):
            request_json(self.base, "/v1/actions")

    async def test_cancelled_caller_does_not_free_a_running_worker_slot(self) -> None:
        entered, release = threading.Event(), threading.Event()
        calls = []
        def slow_request(*args: object) -> tuple:
            calls.append(1)
            entered.set()
            if not release.wait(timeout=1):
                raise TimeoutError("Test release was not signalled")
            return 200, {"complete": True}
        client = TelemetryClient(self.base, concurrency=1)
        with patch("controller.telemetry_client.request_json", side_effect=slow_request):
            first = asyncio.create_task(client.get_stats())
            second = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                second = asyncio.create_task(client.get_stats())
                await asyncio.sleep(0.02)
                self.assertEqual(len(calls), 1)
                release.set()
                self.assertTrue((await second)["complete"])
                self.assertEqual(len(calls), 2)
            finally:
                release.set()
                if second and not second.done():
                    await second


if __name__ == "__main__":
    unittest.main()
