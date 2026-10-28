"""Deterministic telemetry fixtures with known counter arithmetic and invalidations."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import yaml

from controller.core import Fabric
from decision.features import FEATURE_FIELDS, FeatureExtractor, load_config
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]
NS = 1_000_000_000


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.fabric = Fabric(load_plan(ROOT / "configs" / "hospital.yaml"))
        self.config = load_config(ROOT / "configs" / "features.yaml", self.fabric)
        self.config["window_s"] = 2
        self.extractor = FeatureExtractor(self.fabric, self.config)

    def row(self, host="monitor1", dst="central_mon", packets=0, byte_count=None,
            port=18001, age=10, priority=10000):
        source, dest = self.fabric.hosts[host], self.fabric.hosts[dst]
        return {"table_id": 0, "priority": priority, "cookie": "0x10000001",
                "match": {"in_port": source["switch_port"], "eth_type": 0x0800,
                          "ipv4_src": source["address"], "ipv4_dst": dest["address"],
                          "ip_proto": 17, "udp_src": 25000, "udp_dst": port},
                "packets": packets, "bytes": packets * 100 if byte_count is None else byte_count,
                "duration_ns": int(age * NS), "ingress_source_host": "FORGED"}

    def body(self, t, rows=None, obs=None, epoch="a", guards=0):
        rows = rows or []
        switches = []
        for dpid in sorted(self.extractor.expected):
            switch_rows = [r for r in rows if self.fabric.hosts[
                self.fabric.by_ip[r["match"]["ipv4_src"]]["name"]]["access_dpid"] == int(dpid, 16)]
            switches.append({"dpid": dpid, "connected": True, "fresh": True, "error": None,
                "truncated": False, "snapshot": {"generation": 1, "poll": t,
                    "requested_ns": t * NS, "received_ns": t * NS + NS // 10,
                    "rows": copy.deepcopy(switch_rows)}})
        observations = obs or []
        return {"schema_version": 1, "observation_scope": "admitted_source_ingress_packet_ins",
                "complete": True, "controller_epoch": epoch, "timestamp_ns": t * NS + NS // 5,
                "switches": switches, "observations": observations,
                "observation_last_seq": observations[-1]["seq"] if observations else 0,
                "observation_guard_drops": {"source_guard_drops": guards, "global_guard_drops": 0}}

    def ingest(self, t, **kwargs):
        body = self.body(t, **kwargs)
        return self.extractor.ingest(body, body["timestamp_ns"])

    def obs(self, seq, t, host="monitor1", dst="central_mon", port=18001):
        source = self.fabric.hosts[host]
        return {"seq": seq, "timestamp_ns": t * NS, "host": host,
                "src": source["address"], "dst": self.fabric.hosts[dst]["address"],
                "dpid": f"{source['access_dpid']:016x}", "ip_proto": 17,
                "src_port": 25000, "dst_port": port}

    @staticmethod
    def feature(result, host):
        return next(f for f in result["features"] if f["host"] == host)

    def test_exact_contract_counter_deltas_and_sliding_window(self):
        self.assertEqual(self.ingest(10, rows=[self.row(packets=100, age=10)])["status"], "baseline")
        self.assertEqual(self.ingest(11, rows=[self.row(packets=110, age=11)])["status"], "warming")
        result = self.ingest(12, rows=[self.row(packets=125, age=12)])
        monitor = self.feature(result, "monitor1")
        server = self.feature(result, "central_mon")
        self.assertEqual(tuple(monitor), FEATURE_FIELDS)
        self.assertEqual((monitor["pkts_out"], monitor["bytes_out"], monitor["window_s"]), (25, 2500, 2))
        self.assertEqual((server["pkts_in"], server["bytes_in"]), (25, 2500))
        self.assertEqual((monitor["flow_count"], monitor["unique_dst"], monitor["new_peers"]), (1, 1, 1))
        result = self.ingest(13, rows=[self.row(packets=130, age=13)])
        self.assertEqual(self.feature(result, "monitor1")["pkts_out"], 20)
        json.dumps(result, allow_nan=False)

    def test_transit_and_drop_rows_do_not_double_count(self):
        def sample(t, n):
            row = self.row(packets=n, age=t)
            body = self.body(t, rows=[row, self.row(packets=999, priority=40000)])
            transit = copy.deepcopy(row)
            # Same source on a different access switch: recomputed attribution rejects it.
            body["switches"][0]["snapshot"]["rows"].append(transit)
            body["switches"].append({"dpid": "0000000000000001", "snapshot": {"rows": [row]}})
            return self.extractor.ingest(body, body["timestamp_ns"])
        sample(10, 10)
        sample(11, 20)
        result = sample(12, 30)
        self.assertEqual(self.feature(result, "monitor1")["pkts_out"], 20)

    def test_observation_only_flow_is_visible_without_invented_bytes(self):
        self.ingest(10)
        observations = [self.obs(1, 11, dst="reception1", port=20001),
                        self.obs(2, 11, dst="reception2", port=20002)]
        self.ingest(11, obs=observations)
        result = self.ingest(12, obs=observations)
        f = self.feature(result, "monitor1")
        self.assertEqual((f["flow_count"], f["unique_dst"], f["unique_dst_ports"]), (2, 2, 2))
        self.assertEqual((f["pkts_out"], f["bytes_out"], f["short_flows"]), (0, 0, 0))
        self.assertEqual((f["off_allow_list_flows"], f["new_peers"]), (2, 2))

    def test_counter_and_observation_tuple_are_deduplicated(self):
        self.ingest(10, rows=[self.row(packets=0)])
        observations = [self.obs(1, 11)]
        self.ingest(11, rows=[self.row(packets=5, age=11)], obs=observations)
        result = self.ingest(12, rows=[self.row(packets=10, age=12)], obs=observations)
        self.assertEqual(self.feature(result, "monitor1")["flow_count"], 1)

    def test_safe_new_rule_and_short_age_proxy(self):
        self.ingest(10)
        self.ingest(11, rows=[self.row(packets=3, age=0.5)])
        result = self.ingest(12, rows=[self.row(packets=7, age=1.5)])
        f = self.feature(result, "monitor1")
        self.assertEqual((f["pkts_out"], f["short_flows"]), (7, 1))

    def test_critical_wildcard_and_specific_tuple_form_one_group(self):
        def rows(n, age):
            wildcard = self.row(packets=n, age=age, priority=50000)
            wildcard["match"].pop("udp_src")
            return [wildcard]
        self.ingest(10, rows=rows(10, 0.2))
        self.ingest(11, rows=rows(20, 1.2), obs=[self.obs(1, 11)])
        result = self.ingest(12, rows=rows(30, 2.2), obs=[self.obs(1, 11)])
        f = self.feature(result, "monitor1")
        self.assertEqual((f["flow_count"], f["short_flows"], f["pkts_out"]), (1, 1, 20))

    def test_irregular_intervals_report_actual_window_duration(self):
        self.ingest(10)
        self.ingest(12)
        result = self.ingest(15)
        self.assertEqual(self.feature(result, "monitor1")["window_s"], 3)
        self.assertEqual(result["quality"]["actual_window_s"], 3)

    def test_duration_reset_with_increasing_counters_is_not_a_new_rate(self):
        self.ingest(10, rows=[self.row(packets=10, age=10)])
        result = self.ingest(11, rows=[self.row(packets=20, age=1)])
        self.assertEqual(result["reason"], "counter_reset")

    def test_tuple_and_segment_bounds_fail_closed(self):
        self.config["max_observations"] = 1
        self.ingest(10)
        result = self.ingest(11, obs=[self.obs(1, 11), self.obs(2, 11, port=20000)])
        self.assertEqual(result["reason"], "observation_limit")
        self.setUp()
        self.config["max_segments"] = 1
        self.ingest(10)
        self.ingest(11)
        self.assertEqual(self.ingest(12)["reason"], "segment_limit")

    def test_historical_new_row_never_imports_old_totals(self):
        self.ingest(10)
        result = self.ingest(11, rows=[self.row(packets=9000, age=10)])
        self.assertEqual(result["reason"], "unknown_counter_baseline")
        self.assertEqual(result["features"], [])

    def test_counter_reset_disappearance_and_generation_reset_invalidate(self):
        for failure in ("counter_reset", "rule_disappeared", "switch_generation"):
            self.setUp()
            self.ingest(10, rows=[self.row(packets=10)])
            body = self.body(11, rows=[self.row(packets=20, age=11)])
            if failure == "counter_reset":
                body["switches"][-2]["snapshot"]["rows"][0]["packets"] = 0
            elif failure == "rule_disappeared":
                body = self.body(11)
            else:
                body["switches"][0]["snapshot"]["generation"] = 2
            with self.subTest(failure=failure):
                result = self.extractor.ingest(body, body["timestamp_ns"])
                self.assertEqual(result["reason"], failure)
                self.assertFalse(result["features"])

    def test_restart_guard_and_eviction_invalidate_then_rewarm(self):
        self.ingest(10)
        self.ingest(11)
        result = self.ingest(12, obs=[self.obs(4, 12)], guards=2)
        self.assertEqual(result["reason"], "observation_gap_or_guard")
        result = self.ingest(13, obs=[self.obs(4, 12)], guards=2)
        self.assertEqual(result["status"], "warming")
        result = self.ingest(14, obs=[self.obs(4, 12)], guards=2)
        self.assertEqual(result["status"], "ready")
        result = self.ingest(15, epoch="b")
        self.assertEqual(result["reason"], "observation_gap_or_guard")

    def test_stale_partial_missing_and_future_snapshots_rejected(self):
        for failure in ("stale", "partial", "missing", "future", "oversized"):
            self.setUp()
            body = self.body(10)
            now = body["timestamp_ns"]
            if failure == "stale":
                now += 10 * NS
            elif failure == "partial":
                body["complete"] = False
            elif failure == "missing":
                body["switches"].pop()
            elif failure == "future":
                now -= NS
            else:
                self.config["max_rows"] = 0
                body = self.body(10, rows=[self.row()])
            with self.subTest(failure=failure):
                self.assertEqual(self.extractor.ingest(body, now)["status"], "invalid")

    def test_repeated_poll_vector_does_not_emit_zero_traffic_window(self):
        body = self.body(10)
        self.extractor.ingest(body, body["timestamp_ns"])
        self.assertEqual(self.extractor.ingest(body, body["timestamp_ns"] + NS)["status"],
                         "waiting_for_polls")
        result = self.extractor.ingest(body, body["timestamp_ns"] + 3 * NS)
        self.assertNotEqual(result["status"], "ready")

    def test_malformed_counter_and_observation_rejected(self):
        body = self.body(10, rows=[self.row(packets=True)])
        self.assertEqual(self.extractor.ingest(body, body["timestamp_ns"])["status"], "invalid")
        body = self.body(11, obs=[self.obs(1, 11)])
        body["observations"][0]["src"] = "8.8.8.8"
        self.assertEqual(self.extractor.ingest(body, body["timestamp_ns"])["status"], "invalid")

    def test_new_peer_history_expires_and_state_is_bounded(self):
        self.config["peer_history_s"] = 3
        self.ingest(10, rows=[self.row()])
        for t in range(11, 150):
            n = 1 if t < 20 else 2 if t >= 25 else 1
            result = self.ingest(t, rows=[self.row(packets=n, age=t)])
            if t == 25:
                self.assertEqual(self.feature(result, "monitor1")["new_peers"], 1)
            self.assertLessEqual(len(self.extractor.segments), 4)
            self.assertLessEqual(sum(len(p) for p in self.extractor.peer_seen.values()), 24 * 24)
            self.assertLessEqual(len(self.extractor.pending_observations), self.config["max_observations"])

    def test_bad_configuration_unknown_peers_and_unbounded_values(self):
        for key, value in (("window_s", float("nan")), ("max_rows", 0),
                           ("max_segments", 1), ("forward_priorities", [40000]),
                           ("allowed_peer_overrides", {"monitor1": ["internet"]})):
            c = copy.deepcopy(self.config)
            c[key] = value
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "features.yaml"
                path.write_text(yaml.safe_dump(c))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    load_config(path, self.fabric)


if __name__ == "__main__":
    unittest.main()
