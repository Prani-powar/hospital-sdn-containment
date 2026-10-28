"""Bounded sliding features from source-ingress rule counters and packet-in evidence."""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Any

import yaml

from controller.core import Fabric
from controller.telemetry_client import ObservationCursor
from topology.hospital import UniqueKeyLoader, load_plan, require

FEATURE_FIELDS = (
    "timestamp_ns", "window_s", "host", "role", "flow_count", "unique_dst",
    "unique_dst_ports", "bytes_in", "bytes_out", "pkts_in", "pkts_out",
    "new_peers", "off_allow_list_flows", "short_flows",
)


def load_config(path: Path, fabric: Fabric) -> dict:
    """Validate resource limits and an explicit experimental peer profile."""
    require(path.stat().st_size <= 100_000, "Feature config exceeds 100 KB")
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(c, dict) and c.get("schema_version") == 1, "Invalid feature schema")
    for key, low, high in (
        ("window_s", 1, 30), ("max_poll_gap_s", 1, 10),
        ("max_snapshot_age_s", 0.1, 10), ("max_acquisition_s", 0.1, 5),
        ("peer_history_s", 1, 300), ("short_flow_age_s", 0.1, 30),
        ("poll_interval_s", 0.2, 5),
    ):
        v = c.get(key)
        require(type(v) in (int, float) and math.isfinite(v) and low <= v <= high,
                f"Invalid {key}")
    for key, low, high in (("max_rows", 16, 8192), ("max_observations", 16, 4096),
                           ("max_segments", 8, 256)):
        require(type(c.get(key)) is int and low <= c[key] <= high, f"Invalid {key}")
    require(c["peer_history_s"] >= c["window_s"], "Peer history must cover a window")
    require(c["max_segments"] * c["poll_interval_s"] >= c["window_s"] + c["max_poll_gap_s"],
            "Segment limit is too small for configured window")
    require(isinstance(c.get("profile_version"), str) and 0 < len(c["profile_version"]) <= 100,
            "Missing bounded profile version")
    priorities = c.get("forward_priorities")
    require(isinstance(priorities, list) and priorities and len(priorities) <= 3
            and all(type(p) is int and p in (10000, 45000, 50000) for p in priorities)
            and len(set(priorities)) == len(priorities), "Invalid forwarding priorities")
    roles = {h["role"] for h in fabric.hosts.values()}
    profiles = c.get("allowed_peers_by_role")
    overrides = c.get("allowed_peer_overrides")
    require(isinstance(profiles, dict) and set(profiles) == roles, "Every role needs a peer profile")
    require(isinstance(overrides, dict) and set(overrides) <= fabric.hosts.keys(),
            "Unknown host override")
    for peers in list(profiles.values()) + list(overrides.values()):
        require(isinstance(peers, list) and len(peers) <= len(fabric.hosts)
                and all(isinstance(p, str) and p in fabric.hosts for p in peers)
                and len(set(peers)) == len(peers), "Invalid or duplicate peer profile")
    require(isinstance(c.get("summary_hosts"), list) and len(c["summary_hosts"]) <= len(fabric.hosts)
            and all(h in fabric.hosts for h in c["summary_hosts"]), "Invalid summary hosts")
    return c


def integer(value: Any, label: str) -> int:
    """Reject booleans, negatives and non-integer telemetry counters."""
    require(type(value) is int and value >= 0, f"Invalid {label}")
    return value


@dataclass
class Reading:
    """One source-ingress counter instance at a completed acquisition."""
    key: str
    host: str
    dst: str
    proto: int
    sport: int | None
    dport: int | None
    packets: int
    bytes: int
    duration_ns: int
    requested_ns: int
    received_ns: int

    @property
    def tuple(self) -> tuple:
        return self.host, self.dst, self.proto, self.sport, self.dport


def covered(candidate: tuple, rules: set) -> bool:
    """Four indexed lookups avoid quadratic scans during high tuple churn."""
    head, sport, dport = candidate[:3], candidate[3], candidate[4]
    return any((*head, s, d) in rules for s, d in (
        (sport, dport), (None, dport), (sport, None), (None, None)))


def collapse(rules: set) -> set:
    """Coalesce specific tuples already represented by a wildcarded port group."""
    return {t for t in rules if not any(other != t and other in rules for other in (
        (*t[:3], None, t[4]), (*t[:3], t[3], None), (*t[:3], None, None)))}


class FeatureExtractor:
    """Single-owner state machine: baseline -> warming -> valid, with gap resets.

    Flow counts describe observed rule/tuple groups, not TCP sessions. Byte/packet
    totals are source-ingress forwarding-rule hits, not delivered application data.
    """

    def __init__(self, fabric: Fabric, config: dict) -> None:
        self.fabric, self.config = fabric, config
        self.expected = {f"{h['access_dpid']:016x}" for h in fabric.hosts.values()}
        self.allowed = {name: set(config["allowed_peer_overrides"].get(
            name, config["allowed_peers_by_role"][h["role"]])) for name, h in fabric.hosts.items()}
        self.cursor = ObservationCursor()
        self.epoch = None
        self.previous = None
        self.segments = deque()
        self.pending_observations = {}
        self.peer_seen = {name: {} for name in fabric.hosts}
        self.skips = Counter()

    def invalidate(self, reason: str) -> dict:
        """Discard windows and counter baselines instead of turning unknowns into zeros."""
        self.previous = None
        self.segments.clear()
        self.pending_observations.clear()
        self.skips[reason] += 1
        return {"status": "invalid", "reason": reason, "features": []}

    def _readings(self, body: dict, now_ns: int) -> tuple[dict, dict]:
        require(body.get("schema_version") == 1
                and body.get("observation_scope") == "admitted_source_ingress_packet_ins",
                "unsupported_telemetry_schema")
        require(body.get("complete") is True, "incomplete_snapshot")
        stamp = integer(body["timestamp_ns"], "timestamp")
        require(0 <= now_ns - stamp <= self.config["max_snapshot_age_s"] * 1e9,
                "stale_snapshot")
        switches = body["switches"]
        require(isinstance(switches, list) and len(switches) <= len(self.fabric.switches),
                "invalid_switch_inventory")
        snapshots, readings = {}, {}
        row_count = 0
        for switch in switches:
            dpid = switch["dpid"]
            if dpid not in self.expected:
                continue  # Transit core is never counted.
            require(dpid not in snapshots, "duplicate_switch")
            snap = switch.get("snapshot")
            require(switch.get("connected") is True and switch.get("fresh") is True
                    and not switch.get("truncated") and not switch.get("error") and snap,
                    "incomplete_switch")
            req = integer(snap["requested_ns"], "request time")
            recv = integer(snap["received_ns"], "receive time")
            require(0 <= recv - req <= self.config["max_acquisition_s"] * 1e9
                    and 0 <= stamp - recv <= self.config["max_snapshot_age_s"] * 1e9,
                    "invalid_acquisition_time")
            generation = integer(snap["generation"], "generation")
            poll = integer(snap["poll"], "poll")
            require(isinstance(snap["rows"], list), "invalid_rows")
            row_count += len(snap["rows"])
            require(row_count <= self.config["max_rows"], "row_limit")
            snapshots[dpid] = (generation, poll, req, recv)
            for row in snap["rows"]:
                m = row["match"]
                if row["priority"] not in self.config["forward_priorities"] or m.get("eth_type") != 0x0800:
                    continue  # Drops, table miss and ARP are not forwarded IPv4 bytes.
                host = self.fabric.source_for_row(int(dpid, 16), m)
                if host is None:
                    continue  # Recompute attribution; never trust a supplied host label.
                dst = self.fabric.by_ip.get(m.get("ipv4_dst"))
                require(dst is not None and row["table_id"] == 0, "unsupported_forward_row")
                proto = integer(m.get("ip_proto"), "protocol")
                prefix = "tcp" if proto == 6 else "udp" if proto == 17 else None
                sport, dport = (m.get(prefix + "_src"), m.get(prefix + "_dst")) if prefix else (None, None)
                for port in (sport, dport):
                    require(port is None or type(port) is int and 0 <= port <= 65535, "invalid_port")
                key = json.dumps([dpid, row["table_id"], row["priority"], row["cookie"], m], sort_keys=True)
                require(key not in readings, "duplicate_counter_row")
                readings[key] = Reading(key, host, dst["name"], proto, sport, dport,
                    integer(row["packets"], "packets"), integer(row["bytes"], "bytes"),
                    integer(row["duration_ns"], "duration"), req, recv)
        require(set(snapshots) == self.expected, "missing_access_switch")
        return snapshots, readings

    def ingest(self, body: dict, now_ns: int) -> dict:
        """Return exact Feature dictionaries plus separate operational quality metadata."""
        try:
            return self._ingest(body, now_ns)
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError) as exc:
            # Keep finite reason labels rather than arbitrary input-derived counter keys.
            reason = str(exc) if str(exc) in {
                "incomplete_snapshot", "stale_snapshot", "incomplete_switch", "row_limit",
                "missing_access_switch", "duplicate_switch", "invalid_acquisition_time",
                "duplicate_counter_row", "unsupported_forward_row", "invalid_port",
                "observation_limit", "invalid_observation", "observation_time",
            } else "malformed_telemetry"
            return self.invalidate(reason)

    def _ingest(self, body: dict, now_ns: int) -> dict:
        snapshots, readings = self._readings(body, now_ns)
        observations = body["observations"]
        require(isinstance(observations, list) and len(observations) <= self.config["max_observations"],
                "observation_limit")
        require(isinstance(body["controller_epoch"], str) and 0 < len(body["controller_epoch"]) <= 100,
                "invalid_epoch")
        continuity = self.cursor.read(body)
        epoch = body["controller_epoch"]
        if epoch != self.epoch:
            if self.epoch is not None:
                self.invalidate("controller_epoch")
            self.epoch = epoch
            self.peer_seen = {name: {} for name in self.fabric.hosts}
        if not continuity["continuity_ok"]:
            result = self.invalidate("observation_gap_or_guard")
            # Retain a clean starting counter baseline, not the incomplete history.
            self.previous = (now_ns, snapshots, readings)
            result["continuity"] = {k: v for k, v in continuity.items() if k != "new_observations"}
            return result
        for row in continuity["new_observations"]:
            host = self.fabric.hosts.get(row["host"])
            destination = self.fabric.by_ip.get(row["dst"])
            require(host is not None and destination is not None and row["src"] == host["address"]
                    and row["dpid"] == f"{host['access_dpid']:016x}", "invalid_observation")
            stamp = integer(row["timestamp_ns"], "observation time")
            require(0 <= now_ns - stamp <= self.config["max_snapshot_age_s"] * 1e9,
                    "observation_time")
            proto = integer(row["ip_proto"], "observation protocol")
            ports = row.get("src_port"), row.get("dst_port")
            require(all(p is None or type(p) is int and 0 <= p <= 65535 for p in ports),
                    "invalid_observation")
            # Deduplicate tuple evidence between vector advances; counts are never
            # added to forwarding counters because PacketOut and FlowMod can overlap.
            key = host["name"], destination["name"], proto, *ports
            self.pending_observations[key] = stamp
            require(len(self.pending_observations) <= self.config["max_observations"], "observation_limit")
        if self.previous is None:
            self.previous = (now_ns, snapshots, readings)
            self.pending_observations.clear()
            return {"status": "baseline", "features": []}
        start, old_snapshots, old_readings = self.previous
        elapsed = (now_ns - start) / 1e9
        if elapsed <= 0 or elapsed > self.config["max_poll_gap_s"]:
            result = self.invalidate("poll_gap")
            self.previous = (now_ns, snapshots, readings)
            return result
        if any(snapshots[d][0] != old_snapshots[d][0] for d in self.expected):
            result = self.invalidate("switch_generation")
            self.previous = (now_ns, snapshots, readings)
            return result
        if any(snapshots[d][1] < old_snapshots[d][1] for d in self.expected):
            return self.invalidate("poll_regression")
        if any(snapshots[d][1] == old_snapshots[d][1] for d in self.expected):
            return {"status": "waiting_for_polls", "features": []}
        if any(snapshots[d][2] <= old_snapshots[d][3] for d in self.expected):
            return self.invalidate("overlapping_acquisitions")
        if any(snapshots[d][3] - old_snapshots[d][3] > self.config["max_poll_gap_s"] * 1e9
               for d in self.expected):
            result = self.invalidate("switch_poll_gap")
            self.previous = (now_ns, snapshots, readings)
            return result
        if set(old_readings) - readings.keys():
            result = self.invalidate("rule_disappeared")
            self.previous = (now_ns, snapshots, readings)
            return result
        metrics = {name: Counter() for name in self.fabric.hosts}
        active, short = set(), set()
        for key, row in readings.items():
            old = old_readings.get(key)
            if old:
                if row.packets < old.packets or row.bytes < old.bytes or row.duration_ns < old.duration_ns:
                    result = self.invalidate("counter_reset")
                    self.previous = (now_ns, snapshots, readings)
                    return result
                packets, byte_count = row.packets - old.packets, row.bytes - old.bytes
            else:
                # Only count new rules whose earliest possible creation follows
                # the previous acquisition; never import historical totals.
                dpid = json.loads(key)[0]
                if row.requested_ns - row.duration_ns < old_snapshots[dpid][3]:
                    result = self.invalidate("unknown_counter_baseline")
                    self.previous = (now_ns, snapshots, readings)
                    return result
                packets, byte_count = row.packets, row.bytes
            metrics[row.host]["pkts_out"] += packets
            metrics[row.host]["bytes_out"] += byte_count
            metrics[row.dst]["pkts_in"] += packets
            metrics[row.dst]["bytes_in"] += byte_count
            if packets or byte_count:
                active.add(row.tuple)
                if row.duration_ns <= self.config["short_flow_age_s"] * 1e9:
                    short.add(row.tuple)
        for obs in self.pending_observations:
            if not covered(obs, active):
                active.add(obs)
        new_peers = {name: set() for name in self.fabric.hosts}
        for name, history in self.peer_seen.items():
            for peer in [p for p, stamp in history.items()
                         if now_ns - stamp > self.config["peer_history_s"] * 1e9]:
                del history[peer]
        for name, dst, *_ in active:
            if dst not in self.peer_seen[name]:
                new_peers[name].add(dst)
            self.peer_seen[name][dst] = now_ns
        segment = {"start": start, "end": now_ns, "metrics": metrics,
                   "active": active, "short": short, "new": new_peers,
                   "start_acquisitions": old_snapshots}
        self.previous = (now_ns, snapshots, readings)
        self.pending_observations.clear()
        self.segments.append(segment)
        target = now_ns - self.config["window_s"] * 1e9
        while len(self.segments) > 1 and self.segments[1]["start"] <= target:
            self.segments.popleft()
        if len(self.segments) > self.config["max_segments"]:
            return self.invalidate("segment_limit")
        actual_s = (now_ns - self.segments[0]["start"]) / 1e9
        if actual_s < self.config["window_s"]:
            return {"status": "warming", "features": []}
        features = []
        for name, host in self.fabric.hosts.items():
            totals = Counter()
            tuples, short_tuples, peers_new = set(), set(), set()
            for part in self.segments:
                totals.update(part["metrics"][name])
                tuples.update(t for t in part["active"] if t[0] == name)
                short_tuples.update(t for t in part["short"] if t[0] == name)
                peers_new.update(part["new"][name])
            tuples, short_tuples = collapse(tuples), collapse(short_tuples)
            short_groups = set()
            for t in short_tuples:
                for group in ((*t[:3], None, None), (*t[:3], None, t[4]),
                              (*t[:3], t[3], None), t):
                    if group in tuples:
                        short_groups.add(group)
                        break
            feature = dict(timestamp_ns=now_ns, window_s=actual_s, host=name, role=host["role"],
                flow_count=len(tuples), unique_dst=len({t[1] for t in tuples}),
                unique_dst_ports=len({t[4] for t in tuples if t[4] is not None}),
                bytes_in=totals["bytes_in"], bytes_out=totals["bytes_out"],
                pkts_in=totals["pkts_in"], pkts_out=totals["pkts_out"],
                new_peers=len(peers_new),
                off_allow_list_flows=sum(t[1] not in self.allowed[name] for t in tuples),
                short_flows=len(short_groups))
            features.append(feature)
        return {"status": "ready", "features": features,
                "quality": {"valid": True, "profile_version": self.config["profile_version"],
                    "feature_spec_version": "source-ingress-proxy-v1",
                    "counter_scope": "source_ingress_forwarding_rule_hits",
                    "observation_scope": "admitted_source_ingress_packet_ins",
                    "intervals": len(self.segments), "actual_window_s": actual_s,
                    "poll_acquisition_ranges": {
                        d: {"start_requested_ns": self.segments[0]["start_acquisitions"][d][2],
                            "start_received_ns": self.segments[0]["start_acquisitions"][d][3],
                            "end_requested_ns": s[2], "end_received_ns": s[3]}
                        for d, s in snapshots.items()}}}


def from_files(topology_path: Path, config_path: Path) -> FeatureExtractor:
    """Construct an extractor without Ryu, Mininet imports or network writes."""
    fabric = Fabric(load_plan(topology_path))
    return FeatureExtractor(fabric, load_config(config_path, fabric))
