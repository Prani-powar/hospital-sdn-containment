"""Rule-plan and test-runner checks; real OVS behaviour still needs Mint."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from topology.clinical import load_config as load_traffic
from topology.hospital import load_plan
from topology import restriction_demo as demo

ROOT = Path(__file__).resolve().parents[2]


class RestrictionTests(unittest.TestCase):
    """Verify priorities, exact paths, honest evidence and failure handling."""

    def setUp(self) -> None:
        self.topology = load_plan(ROOT / "configs" / "hospital.yaml")
        self.traffic = load_traffic(ROOT / "configs" / "clinical.yaml", self.topology)
        self.config = yaml.safe_load((ROOT / "configs" / "restriction-demo.yaml").read_text())

    def test_forward_and_reverse_paths_use_explicit_correct_ports(self) -> None:
        self.assertEqual(demo.route(self.topology, "monitor1", "central_mon"),
                         [("s_iomt", 1), ("s_core", 3), ("s_server", 6)])
        self.assertEqual(demo.route(self.topology, "central_mon", "monitor1"),
                         [("s_server", 1), ("s_core", 4), ("s_iomt", 2)])

    def test_specific_allows_precede_drop_on_ingress(self) -> None:
        rules = demo.critical_rules(self.topology, self.traffic)
        self.assertEqual(sum(map(len, rules.values())), 18)
        cookies = set()
        for group in rules.values():
            for rule in group:
                self.assertIn("priority=50000,udp,nw_src=10.20.0.", rule)
                self.assertIn("nw_dst=10.20.0.", rule)
                self.assertTrue("tp_src=18001" in rule or "tp_dst=18001" in rule)
                self.assertIn("actions=output:", rule)
                self.assertNotIn("NORMAL", rule)
                cookies.add(rule.split(",")[0])
        self.assertEqual(len(cookies), 18)
        bridge, drop = demo.drop_rule(self.topology, self.config)
        self.assertEqual(bridge, "s_iomt")
        self.assertIn("priority=40000,ip,nw_src=10.20.0.16", drop)
        self.assertIn("hard_timeout=10", drop)
        self.assertTrue(drop.endswith("actions=drop"))

    def test_reject_missing_traffic_wrong_target_and_unsafe_timing(self) -> None:
        with self.assertRaises(ValueError):
            demo.load_config(ROOT / "configs" / "restriction-demo.yaml", self.topology, None)
        for field, value in (("target", "ehr"), ("target", "reception1"),
                             ("quarantine_timeout_s", 0), ("quarantine_timeout_s", 8),
                             ("minimum_success_rate", 0), ("minimum_probes", 100)):
            bad = copy.deepcopy(self.config)
            bad[field] = value
            # TTL 8 with phase 5 leaves no room for the ping control.
            if field == "quarantine_timeout_s" and value == 8:
                bad["phase_s"] = 5
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "demo.yaml"
                path.write_text(yaml.safe_dump(bad))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    demo.load_config(path, self.topology, self.traffic)
        self.traffic["duration_s"] = 10
        with self.assertRaises(ValueError):
            demo.load_config(ROOT / "configs" / "restriction-demo.yaml",
                             self.topology, self.traffic)

    def test_exact_cookie_filter_ignores_headers_and_longer_cookie(self) -> None:
        raw = ("OFPST_FLOW reply\n cookie=0x123, n_packets=2\n"
               " cookie=0x1234, n_packets=999\n cookie=0x12, n_packets=8")
        self.assertEqual(demo.cookie_records(raw, 0x123), [" cookie=0x123, n_packets=2"])

    def test_phase_metrics_do_not_count_stale_or_outside_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor1.jsonl"
            records = [{"check": "c1_probe", "timestamp_ns": ns,
                        "success": ok, "rtt_ms": 2 if ok else None}
                       for ns, ok in ((1, True), (100, True), (199, False), (200, True))]
            path.write_text("\n".join(json.dumps(p) for p in records) + '\n{"partial":')
            result = demo.samples(path, 100, 200)
            self.assertEqual(result["attempted"], 2)
            self.assertEqual(result["received"], 1)
            self.assertEqual(result["success_rate"], 0.5)

    def test_stopped_worker_cannot_pass_on_old_metrics(self) -> None:
        class DeadWorker:
            def poll(self) -> int:
                return 0
        class Manager:
            processes = [("monitor1", DeadWorker())]
        with self.assertRaises(ValueError):
            demo.workers_live(Manager())

    def exercise_runner(self, ping_codes: list[int], drop_packets: int) -> dict:
        """Drive outcomes rather than claim to simulate switch behaviour."""
        class LiveWorker:
            def poll(self) -> None:
                return None
        codes = iter(ping_codes)
        class Host:
            def pexec(self, command: list) -> tuple:
                return "synthetic ping control", "", next(codes)
        class Network:
            def get(self, host: str) -> Host:
                return Host()
        class Manager:
            run_id = "unit-run"
            processes = [("monitor1", LiveWorker())]
        allows = demo.critical_rules(self.topology, self.traffic)
        reads = 0
        commands = []

        def fake_ofctl(*args: str, stdin: str | None = None) -> str:
            nonlocal reads
            commands.append((args, stdin))
            if args[0] == "dump-flows" and args[2] == f"cookie=0x{demo.DROP_COOKIE:x}/-1":
                reads += 1
                return (f" cookie=0x{demo.DROP_COOKIE:x}, priority=40000, n_packets={drop_packets}"
                        if reads <= 2 else "")
            if args[0] == "dump-flows":
                return "\n".join(" " + rule for rule in allows[args[1]])
            return ""

        with tempfile.TemporaryDirectory() as directory:
            manager = Manager()
            manager.directory = Path(directory)
            for source in self.traffic["sources"]:
                (manager.directory / f"{source}.jsonl").write_text("\n".join(
                    json.dumps({"check": "c1_probe", "timestamp_ns": ns,
                                "success": True, "rtt_ms": 1})
                    for ns in (150, 450, 750)))
            c = dict(self.config, minimum_probes=1)
            with patch.object(demo, "ofctl", side_effect=fake_ofctl), \
                 patch.object(demo, "emit"), patch.object(demo.time, "sleep"), \
                 patch.object(demo.time, "monotonic_ns",
                              side_effect=[100, 200, 300, 400, 500, 600, 700, 800]):
                try:
                    demo.run(Network(), self.topology, self.traffic, manager, c)
                except ValueError:
                    pass
            report = json.loads((manager.directory / "restriction-report.json").read_text())
            self.assertFalse(any(args[0].startswith("del") for args, _ in commands))
            self.assertEqual(commands[0][0][0], "add-flows")
            return report

    def test_three_phases_and_expiry_evidence_are_persisted(self) -> None:
        result = self.exercise_runner([0, 1, 0], 2)
        self.assertTrue(result["passed"])
        self.assertEqual([p["phase"] for p in result["phases"]],
                         ["before", "restricted", "recovered"])
        self.assertEqual(result["phases"][1]["drop_packets"], 2)

    def test_ping_error_or_zero_drop_matches_cannot_count_as_success(self) -> None:
        self.assertFalse(self.exercise_runner([2], 2)["passed"])
        result = self.exercise_runner([0, 1], 0)
        self.assertFalse(result["passed"])
        self.assertIn("active drop rule", result["error"])


if __name__ == "__main__":
    unittest.main()
