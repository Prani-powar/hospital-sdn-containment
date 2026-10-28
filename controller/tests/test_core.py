"""Unprivileged controller state tests without importing Ryu."""
import copy
from pathlib import Path
import tempfile
import unittest

import yaml

from controller.core import (Fabric, NORMAL_PREFIX, RuleBudget, StatsCache, TokenBucket,
                             flow_identity, ipv4_match, load_plan, load_settings)

ROOT = Path(__file__).resolve().parents[2]


class FabricTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fabric = Fabric(load_plan(ROOT / "configs" / "hospital.yaml"))
        self.settings = load_settings(ROOT / "configs" / "controller.yaml")

    def test_configured_paths_and_source_attachment(self) -> None:
        m = self.fabric.hosts["monitor1"]
        c = self.fabric.hosts["central_mon"]
        self.assertEqual(self.fabric.ports[(0x14, c["mac"])], 1)
        self.assertEqual(self.fabric.ports[(1, c["mac"])], 3)
        self.assertEqual(self.fabric.ports[(0x13, c["mac"])], 6)
        self.assertTrue(self.fabric.valid_source(0x14, 2, m["mac"]))
        self.assertFalse(self.fabric.valid_source(0x14, 3, m["mac"]))
        self.assertTrue(self.fabric.is_ingress(0x14, 2, m["mac"]))
        self.assertFalse(self.fabric.is_ingress(1, 4, m["mac"]))
        self.assertFalse(self.fabric.valid_source(1, 4, "00:00:00:00:00:00"))

    def test_ingress_attribution_avoids_counting_transit_copies(self) -> None:
        row = {"ipv4_src": "10.20.0.16", "in_port": 2}
        self.assertEqual(self.fabric.source_for_row(0x14, row), "monitor1")
        self.assertIsNone(self.fabric.source_for_row(1, row))
        self.assertIsNone(self.fabric.source_for_row(0x13, row))
        self.assertIsNone(self.fabric.source_for_row(0x14, dict(row, in_port=3)))
        self.assertEqual(self.fabric.source_for_row(0x14, {"ipv4_src": "10.20.0.16"}), "monitor1")

    def test_transport_match_prerequisites_and_ports(self) -> None:
        for protocol, prefix in ((6, "tcp"), (17, "udp")):
            m = ipv4_match(2, "a", "b", "10.20.0.16", "10.20.0.15", protocol, 25000, 18001)
            self.assertEqual(m["eth_type"], 0x0800)
            self.assertEqual(m["ip_proto"], protocol)
            self.assertEqual(m[prefix + "_src"], 25000)
            self.assertEqual(m[prefix + "_dst"], 18001)
        with self.assertRaises(ValueError):
            ipv4_match(2, "a", "b", "x", "y", 17)
        m = ipv4_match(2, "a", "b", "x", "y", 1, icmp_type=8, icmp_code=0)
        self.assertEqual(m["icmpv4_type"], 8)
        self.assertNotIn("udp_dst", m)

    def test_normal_cookie_namespace_and_staggered_expiry(self) -> None:
        cookies, expiries = [], set()
        for port in range(30):
            cookie, expiry = flow_identity({"udp_dst": port}, self.settings)
            cookies.append(cookie)
            expiries.add(expiry)
            self.assertEqual(cookie >> 48, NORMAL_PREFIX >> 48)
            self.assertTrue(120 <= expiry <= 150)
            self.assertEqual(flow_identity({"udp_dst": port}, self.settings), (cookie, expiry))
        self.assertEqual(len(set(cookies)), 30)
        self.assertGreater(len(expiries), 1)

    def test_config_rejects_unbounded_resources_or_invalid_timeouts(self) -> None:
        for key, value in (("max_rows_per_switch", 0), ("packet_in_rate", True),
                           ("normal_hard_timeout_s", 0), ("send_timeout_s", 0),
                           ("poll_interval_s", float("nan")), ("poll_core", 1)):
            c = copy.deepcopy(self.settings)
            c[key] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "controller.yaml"
                path.write_text(yaml.safe_dump(c))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    load_settings(path)


class BoundedStateTests(unittest.TestCase):
    def test_token_bucket_refills_without_queue_or_burst_growth(self) -> None:
        bucket = TokenBucket(2, 2)
        self.assertTrue(bucket.take(0))
        self.assertTrue(bucket.take(0))
        self.assertFalse(bucket.take(0.4))
        self.assertTrue(bucket.take(0.5))
        self.assertFalse(bucket.take(0.5))
        for _ in range(2):
            self.assertTrue(bucket.take(100))
        self.assertFalse(bucket.take(100))

    def test_rule_budget_bounds_rules_even_without_flow_stats(self) -> None:
        budget = RuleBudget([1], 2)
        self.assertTrue(budget.admit(1, 0, 150, {"udp_dst": 1}))
        self.assertTrue(budget.admit(1, 1, 150, {"udp_dst": 2}))
        self.assertFalse(budget.admit(1, 30, 150, {"udp_dst": 3}))
        self.assertTrue(budget.admit(1, 150, 150, {"udp_dst": 3}))
        self.assertEqual(len(budget.leases[1]), 2)

    def test_duplicate_matches_renew_without_consuming_extra_slots(self) -> None:
        budget = RuleBudget([1, 2], 2)
        for now in range(100):
            self.assertTrue(budget.admit(1, now, 150, {"in_port": 2, "udp_dst": 80}))
        self.assertEqual(len(budget.leases[1]), 1)
        self.assertTrue(budget.admit(1, 100, 150, {"udp_dst": 81}))
        self.assertTrue(budget.admit(1, 101, 150, {"udp_dst": 80, "in_port": 2}))
        self.assertFalse(budget.admit(1, 151, 150, {"udp_dst": 82}))
        self.assertTrue(budget.admit(2, 151, 150, {"udp_dst": 82}))
        self.assertTrue(budget.admit(1, 250, 150, {"udp_dst": 82}))
        self.assertEqual(len(budget.leases[1]), 2)

    def test_expiry_scan_handles_renewed_earlier_entries(self) -> None:
        budget = RuleBudget([1], 2)
        budget.admit(1, 0, 150, {"udp_dst": 1})
        budget.admit(1, 1, 150, {"udp_dst": 2})
        budget.admit(1, 100, 150, {"udp_dst": 1})
        self.assertTrue(budget.admit(1, 151, 150, {"udp_dst": 3}))
        self.assertFalse(budget.admit(1, 152, 150, {"udp_dst": 4}))


class PollTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = load_settings(ROOT / "configs" / "controller.yaml")
        self.cache = StatsCache([0x11, 0x14], self.settings)
        for dpid in (0x11, 0x14):
            self.cache.register(dpid)

    def complete(self, dpid: int, xid: int = 1, start: int = 0) -> None:
        self.assertTrue(self.cache.begin(dpid, xid, start))
        self.assertTrue(self.cache.accept(dpid, xid, [{"packets": 10}], False, start + 100))

    def test_multipart_is_hidden_until_final_and_rows_are_copied(self) -> None:
        self.cache.begin(0x11, 1, 0)
        self.assertFalse(self.cache.accept(0x11, 1, [{"packets": 2}], True, 10))
        self.assertIsNone(self.cache.view(20)["switches"][0]["snapshot"])
        self.assertTrue(self.cache.accept(0x11, 1, [{"packets": 3}], False, 30))
        view = self.cache.view(40)
        self.assertEqual(len(view["switches"][0]["snapshot"]["rows"]), 2)
        view["switches"][0]["snapshot"]["rows"].clear()
        self.assertEqual(len(self.cache.view(50)["switches"][0]["snapshot"]["rows"]), 2)
        self.assertFalse(view["complete"])  # The second switch has no completed poll.

    def test_overlap_timeout_and_stale_xid(self) -> None:
        self.assertTrue(self.cache.begin(0x11, 1, 0))
        self.assertFalse(self.cache.begin(0x11, 2, 1_000_000_000))
        self.assertTrue(self.cache.begin(0x11, 3, 3_000_000_000))
        self.assertFalse(self.cache.accept(0x11, 1, [], False, 3_000_000_100))
        self.assertEqual(self.cache.states[0x11]["timeouts"], 1)
        self.assertTrue(self.cache.accept(0x11, 3, [], False, 3_000_000_200))

    def test_missing_disconnect_reconnect_and_generation_reset(self) -> None:
        self.complete(0x11)
        self.complete(0x14)
        self.assertTrue(self.cache.view(1000)["complete"])
        self.assertFalse(self.cache.view(4_000_000_000)["complete"])
        self.cache.disconnect(0x14)
        self.assertFalse(self.cache.view(1000)["complete"])
        self.cache.register(0x14)
        self.assertEqual(self.cache.states[0x14]["generation"], 2)
        self.assertIsNone(self.cache.states[0x14]["snapshot"])

    def test_overflow_late_reply_and_api_truncation_are_not_complete(self) -> None:
        self.settings["max_rows_per_switch"] = 2
        self.cache.begin(0x11, 1, 0)
        self.assertFalse(self.cache.accept(0x11, 1, [{}, {}, {}], False, 100))
        self.assertIn("resource limit", self.cache.states[0x11]["last_error"])
        self.cache.begin(0x11, 2, 0)
        self.assertFalse(self.cache.accept(0x11, 2, [], False, 3_000_000_000))
        self.assertIn("late", self.cache.states[0x11]["last_error"])
        self.complete(0x11, 3)
        self.complete(0x14, 4)
        self.settings["max_api_rows"] = 1
        self.assertFalse(self.cache.view(1000)["complete"])
        self.assertTrue(self.cache.view(1000)["switches"][1]["truncated"])

    def test_old_errors_cannot_clear_new_request(self) -> None:
        self.cache.begin(0x11, 7, 0)
        self.cache.reject(0x11, 6, "stale failure")
        self.assertEqual(self.cache.states[0x11]["pending"]["xid"], 7)
        self.cache.reject(0x11, 7, "actual failure")
        self.assertIsNone(self.cache.states[0x11]["pending"])
        self.assertEqual(self.cache.states[0x11]["last_error"], "actual failure")


if __name__ == "__main__":
    unittest.main()
