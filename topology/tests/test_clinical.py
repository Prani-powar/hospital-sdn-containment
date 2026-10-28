"""Clinical probe tests including a real, bounded local UDP exchange."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest

import yaml

from topology.clinical import (ClinicalTraffic, load_config, packet, probe_once,
                               reply_allowed, serve, status)
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]


class ClinicalTests(unittest.TestCase):
    """Exercise actual request/reply handling and the traffic-volume guards."""

    def setUp(self) -> None:
        self.topology = load_plan(ROOT / "configs" / "hospital.yaml")
        self.config = yaml.safe_load((ROOT / "configs" / "clinical.yaml").read_text())

    def validate(self, config: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clinical.yaml"
            path.write_text(yaml.safe_dump(config))
            return load_config(path, self.topology)

    def test_valid_endpoint_mapping(self) -> None:
        c = self.validate(self.config)
        self.assertEqual(c["server_ip"], "10.20.0.15")
        self.assertEqual(c["sources"], ["monitor1", "monitor2", "monitor3"])
        self.assertEqual(c["rate_hz"], 10)

    def test_reject_wrong_role_unknown_host_duplicate_source(self) -> None:
        for sources in (["reception1"], ["outside"], ["monitor1", "monitor1"]):
            bad = copy.deepcopy(self.config)
            bad["sources"] = sources
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                self.validate(bad)
        self.config["server"] = "guest1"
        with self.assertRaises(ValueError):
            self.validate(self.config)

    def test_bound_rate_duration_ports_and_waits(self) -> None:
        for field, value in (("rate_hz", 0), ("rate_hz", 1000), ("rate_hz", True),
                             ("duration_s", 0), ("duration_s", 301), ("udp_port", 0),
                             ("startup_timeout_s", 0), ("reply_timeout_s", 0),
                             ("reply_timeout_s", 0.1), ("reply_timeout_s", float("nan"))):
            bad = copy.deepcopy(self.config)
            bad[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate(bad)

    def test_reject_malformed_foreign_and_oversized_messages(self) -> None:
        raw = packet("run", "monitor1", 1, 10)
        self.assertTrue(reply_allowed(raw, {"monitor1"}, "run"))
        for bad in (b"not-json", b"[]", b"x" * 1025,
                    packet("wrong-run", "monitor1", 1, 10),
                    packet("run", "guest1", 1, 10)):
            self.assertFalse(reply_allowed(bad, {"monitor1"}, "run"))
        data = json.loads(raw)
        data["seq"] = True
        self.assertFalse(reply_allowed(json.dumps(data).encode(), {"monitor1"}, "run"))

    def test_real_local_udp_echo_and_malformed_packet_drop(self) -> None:
        ready = threading.Event()
        ports, failures = [], []

        def on_ready(port: int) -> None:
            ports.append(port)
            ready.set()

        def worker() -> None:
            try:
                serve("127.0.0.1", 0, 0.5, "unit-run", {"monitor1"}, ready=on_ready)
            except Exception as exc:
                failures.append(exc)
                ready.set()

        with contextlib.redirect_stdout(io.StringIO()):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            try:
                self.assertTrue(ready.wait(timeout=2), "Echo server failed to start")
                self.assertFalse(failures)
                peer = ("127.0.0.1", ports[0])
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    rtt = probe_once(sock, peer, packet("unit-run", "monitor1", 1, 10), 0.2)
                    self.assertIsNotNone(rtt)
                    self.assertGreaterEqual(rtt, 0)
                    self.assertIsNone(probe_once(sock, peer, b"invalid", 0.03))
            finally:
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures)

    def test_ignore_wrong_echo_without_accepting_it_as_success(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.responses = iter([(b"stale", ("127.0.0.1", 19001)),
                                       (b"expected", ("127.0.0.1", 19002)),
                                       (b"expected", ("127.0.0.1", 19001))])
            def sendto(self, raw: bytes, peer: tuple) -> None:
                pass
            def settimeout(self, timeout: float) -> None:
                pass
            def recvfrom(self, limit: int) -> tuple:
                return next(self.responses)
        self.assertIsNotNone(probe_once(FakeSocket(), ("127.0.0.1", 19001), b"expected", 1))

    def test_status_counts_only_complete_probe_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run1"
            run.mkdir()
            (run / "run.json").write_text(json.dumps({"sources": ["monitor1"]}))
            rows = [{"check": "c1_probe", "success": True, "rtt_ms": 2.0},
                    {"check": "c1_probe", "success": False, "rtt_ms": None}]
            (run / "monitor1.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + '\n{"incomplete":')
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                status(root)
            record = json.loads(capture.getvalue())
            self.assertEqual(record["attempted"], 2)
            self.assertEqual(record["received"], 1)
            self.assertEqual(record["success_rate"], 0.5)
            self.assertEqual(record["mean_rtt_ms"], 2)

    def test_cleanup_escalates_only_owned_stuck_worker(self) -> None:
        class StuckProcess:
            returncode = None
            killed = terminated = False
            def poll(self) -> None:
                return None
            def terminate(self) -> None:
                self.terminated = True
            def kill(self) -> None:
                self.killed = True
            def wait(self, timeout: int) -> int:
                if not self.killed:
                    raise subprocess.TimeoutExpired("test-worker", timeout)
                self.returncode = -9
                return -9
        with tempfile.TemporaryDirectory() as directory:
            manager = ClinicalTraffic(None, {}, Path(directory))
            process = StuckProcess()
            stream = io.StringIO()
            manager.processes = [("monitor1", process)]
            manager.streams = [stream]
            with contextlib.redirect_stdout(io.StringIO()):
                manager.stop()
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertTrue(stream.closed)

    def test_partial_start_failure_can_be_cleaned_up(self) -> None:
        class FailedHost:
            def popen(self, *args: object, **kwargs: object) -> None:
                assert "HOSPITAL_ACTION_TOKEN" not in kwargs.get("env", {})
                assert "HOSPITAL_ENABLE_ACTIONS" not in kwargs.get("env", {})
                raise OSError("Simulated process launch failure")
        class FailedNet:
            def get(self, host: str) -> FailedHost:
                return FailedHost()
        with tempfile.TemporaryDirectory() as directory:
            c = self.validate(self.config)
            manager = ClinicalTraffic(FailedNet(), c, Path(directory))
            with self.assertRaises(OSError):
                manager.start()
            manager.stop()
            self.assertTrue(all(stream.closed for stream in manager.streams))

    def test_actual_local_worker_processes_and_summaries(self) -> None:
        class LocalHost:
            def popen(self, args: list, **kwargs: object) -> subprocess.Popen:
                return subprocess.Popen(args, **kwargs)
        class LocalNetwork:
            def get(self, host: str) -> LocalHost:
                return LocalHost()
        # This is ordinary loopback, not a Mininet namespace integration test.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        c = self.validate(self.config)
        c.update(server_ip="127.0.0.1", udp_port=port, duration_s=1, rate_hz=5)
        with tempfile.TemporaryDirectory() as directory:
            manager = ClinicalTraffic(LocalNetwork(), c, Path(directory))
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    manager.start()
                    for host, process in manager.processes:
                        if host in c["sources"]:
                            self.assertEqual(process.wait(timeout=4), 0)
                    for source in c["sources"]:
                        records = [json.loads(line) for line in
                                   (manager.directory / f"{source}.jsonl").read_text().splitlines()]
                        summary = next(p for p in records if p["check"] == "c1_summary")
                        self.assertGreater(summary["attempted"], 0)
                        self.assertEqual(summary["success_rate"], 1.0)
                finally:
                    manager.stop()
            self.assertTrue(all(p.poll() is not None for _, p in manager.processes))


if __name__ == "__main__":
    unittest.main()
