"""Exercise the finite collector through real local HTTP and JSONL output."""
import argparse
import asyncio
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

import yaml

from controller.core import Fabric
from decision.collect_features import collect
from decision.features import FEATURE_FIELDS
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]


class CollectorTests(unittest.TestCase):
    def test_real_http_collection_events_features_and_exclusive_output(self):
        fabric = Fabric(load_plan(ROOT / "configs" / "hospital.yaml"))
        started = time.monotonic_ns()
        requests = []
        class Handler(BaseHTTPRequestHandler):
            sequence = 0
            def do_GET(self):
                requests.append(self.path)
                Handler.sequence += 1
                stamp = time.monotonic_ns()
                row = {"table_id": 0, "priority": 10000, "cookie": "0x10000001",
                    "match": {"in_port": 2, "eth_type": 2048, "ipv4_src": "10.20.0.16",
                              "ipv4_dst": "10.20.0.15", "ip_proto": 17,
                              "udp_src": 25000, "udp_dst": 18001},
                    "packets": Handler.sequence * 10, "bytes": Handler.sequence * 1000,
                    "duration_ns": stamp - started}
                switches = [{"dpid": f"{dpid:016x}", "connected": True, "fresh": True,
                    "truncated": False, "error": None, "snapshot": {
                        "generation": 1, "poll": Handler.sequence,
                        "requested_ns": stamp - 1_000_000, "received_ns": stamp - 500_000,
                        "rows": [row] if dpid == 0x14 else []}}
                    for dpid in sorted({h["access_dpid"] for h in fabric.hosts.values()})]
                body = {"schema_version": 1, "observation_scope": "admitted_source_ingress_packet_ins",
                    "complete": True, "controller_epoch": "test-real-http",
                    "timestamp_ns": stamp, "switches": switches, "observations": [],
                    "observation_last_seq": 0,
                    "observation_guard_drops": {"source_guard_drops": 0, "global_guard_drops": 0}}
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = yaml.safe_load((ROOT / "configs" / "features.yaml").read_text())
                config.update(window_s=1, poll_interval_s=0.2)
                config_path = Path(directory) / "features.yaml"
                config_path.write_text(yaml.safe_dump(config))
                output = Path(directory) / "data.jsonl"
                args = argparse.Namespace(topology=ROOT / "configs" / "hospital.yaml",
                    config=config_path, output=output, samples=9,
                    base_url=f"http://127.0.0.1:{server.server_port}")
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    result = asyncio.run(collect(args))
                self.assertEqual(result, 0)
                records = [json.loads(line) for line in output.read_text().splitlines()]
                events = [r for r in records if "stage" in r]
                features = [r for r in records if r.get("check") == "feature_window"]
                self.assertEqual(sum(e["stage"] == "poll_received" for e in events), 9)
                self.assertGreaterEqual(len(features), 24)
                self.assertTrue(all(set(e) == {"run_id", "timestamp_ns", "stage", "host", "details"}
                                    for e in events))
                self.assertEqual(tuple(features[0]["feature"]), FEATURE_FIELDS)
                self.assertTrue(all(f["quality"]["valid"] for f in features))
                monitor = [f for f in features if f["feature"]["host"] == "monitor1"]
                # The server adds ten packets per completed acquisition, independent
                # of scheduler delays. Exact deltas are stronger than assuming
                # five polls always fit inside a wall-clock second.
                self.assertTrue(all(f["feature"]["pkts_out"] == 10*f["quality"]["intervals"]
                                    and f["feature"]["bytes_out"] == 1000*f["quality"]["intervals"]
                                    for f in monitor))
                self.assertEqual(requests, ["/v1/stats"] * 9)
                self.assertEqual(json.loads(stdout.getvalue().splitlines()[-1])["check"], "features_summary")
                original = output.read_bytes()
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
                    asyncio.run(collect(args))
                self.assertEqual(output.read_bytes(), original)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
