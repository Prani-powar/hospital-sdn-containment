"""Pure, bounded topology and telemetry state; no Ryu/eventlet dependency."""
from __future__ import annotations

from collections import defaultdict, deque
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

import yaml

from topology.hospital import UniqueKeyLoader, load_plan, require

NORMAL_PREFIX = 0x1000000000000000
NORMAL_PRIORITY = 10000


def load_settings(path: Path) -> dict:
    """Validate controller resource limits and forwarding timeouts."""
    require(path.stat().st_size <= 100_000, "Controller configuration exceeds 100 KB")
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(c, dict) and c.get("schema_version") == 1, "Invalid controller schema")
    integer_bounds = {
        "policy_version": (1, 65535), "max_rows_per_switch": (16, 4096),
        "max_multipart_parts": (1, 64), "max_api_rows": (16, 8192),
        "normal_idle_timeout_s": (1, 120), "normal_hard_timeout_s": (10, 300),
        "hard_timeout_jitter_s": (0, 60), "normal_rule_limit_per_switch": (16, 2048),
        "packet_in_rate": (10, 10000), "packet_in_burst": (10, 10000),
        "source_packet_in_rate": (10, 2000), "source_packet_in_burst": (10, 2000),
        "flow_mod_rate": (1, 1000), "flow_mod_burst": (1, 1000),
        "observation_limit": (16, 4096),
    }
    for key, (low, high) in integer_bounds.items():
        require(type(c.get(key)) is int and low <= c[key] <= high,
                f"{key} must be an integer in {low}..{high}")
    for key in ("poll_interval_s", "poll_timeout_s", "max_snapshot_age_s", "send_timeout_s",
                "guard_cooldown_s"):
        require(type(c.get(key)) in (float, int) and 0.1 <= c[key] <= 30,
                f"{key} must be a finite number in 0.1..30")
    require(c["poll_timeout_s"] >= c["poll_interval_s"], "Poll timeout is too short")
    require(c["max_snapshot_age_s"] >= c["poll_timeout_s"], "Snapshot age is too short")
    require(type(c.get("poll_core")) is bool, "poll_core must be boolean")
    require(c["normal_idle_timeout_s"] <= c["normal_hard_timeout_s"],
            "Normal idle timeout exceeds hard timeout")
    return c


class TokenBucket:
    """Constant-memory admission counter with an injected monotonic clock."""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate, self.burst = rate, burst
        self.tokens = float(burst)
        self.updated: float | None = None

    def take(self, now: float) -> bool:
        """Admit one item or reject without accumulating a queue."""
        if self.updated is not None:
            self.tokens = min(self.burst, self.tokens + max(0, now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Fabric:
    """Frozen configured host identities and deterministic switch output ports."""

    def __init__(self, topology: dict) -> None:
        self.topology = topology
        self.switches = {int(s["dpid"], 16): s["name"] for s in topology["switches"]}
        by_name = {s["name"]: dpid for dpid, s in
                   ((int(s["dpid"], 16), s) for s in topology["switches"])}
        self.hosts = {}
        for item in topology["hosts"]:
            h = dict(item, address=str(ipaddress.IPv4Interface(item["ip"]).ip),
                     access_dpid=by_name[item["switch"]])
            self.hosts[item["name"]] = h
        self.by_mac = {h["mac"]: h for h in self.hosts.values()}
        self.by_ip = {h["address"]: h for h in self.hosts.values()}
        adjacent = defaultdict(list)
        for link in topology["links"]:
            adjacent[link["node1"]].append((link["node2"], link["port1"]))
            adjacent[link["node2"]].append((link["node1"], link["port2"]))
        self.ports = {}
        for dpid, switch in self.switches.items():
            queue = deque([(switch, None)])
            seen = {switch}
            while queue:
                node, first_port = queue.popleft()
                if node in self.hosts:
                    self.ports[(dpid, self.hosts[node]["mac"])] = first_port
                for peer, port in adjacent[node]:
                    if peer not in seen:
                        seen.add(peer)
                        queue.append((peer, port if first_port is None else first_port))
        require(len(self.ports) == len(self.switches) * len(self.hosts),
                "Fabric is disconnected")

    def valid_source(self, dpid: int, in_port: int, mac: str) -> bool:
        """Reject source MACs arriving through an unexpected configured port."""
        return mac in self.by_mac and self.ports.get((dpid, mac)) == in_port

    def is_ingress(self, dpid: int, in_port: int, mac: str) -> bool:
        """True only at the source host's access attachment."""
        h = self.by_mac.get(mac)
        return bool(h and h["access_dpid"] == dpid and h["switch_port"] == in_port)

    def source_for_row(self, dpid: int, match: dict) -> str | None:
        """Attribute source IPv4 counters once, at their configured ingress switch."""
        h = self.by_ip.get(match.get("ipv4_src"))
        if h and h["access_dpid"] == dpid and match.get("in_port", h["switch_port"]) == h["switch_port"]:
            return h["name"]
        return None


def ipv4_match(in_port: int, src_mac: str, dst_mac: str, src: str, dst: str,
               proto: int, source_port: int | None = None,
               destination_port: int | None = None,
               icmp_type: int | None = None, icmp_code: int | None = None) -> dict:
    """Return specific OF1.3 fields with their required protocol prerequisites."""
    m = {"in_port": in_port, "eth_type": 0x0800, "eth_src": src_mac,
         "eth_dst": dst_mac, "ipv4_src": src, "ipv4_dst": dst, "ip_proto": proto}
    if proto in (6, 17):
        require(source_port is not None and destination_port is not None,
                "TCP/UDP headers were incomplete")
        prefix = "tcp" if proto == 6 else "udp"
        m[prefix + "_src"], m[prefix + "_dst"] = source_port, destination_port
    if proto == 1:
        require(icmp_type is not None and icmp_code is not None, "ICMP header was incomplete")
        m["icmpv4_type"], m["icmpv4_code"] = icmp_type, icmp_code
    return m


def flow_identity(match: dict, settings: dict) -> tuple[int, int]:
    """Stable normal-rule cookie and staggered hard expiry; never a critical cookie."""
    digest = int.from_bytes(hashlib.blake2s(
        json.dumps(match, sort_keys=True).encode(), digest_size=4).digest(), "big")
    cookie = NORMAL_PREFIX | (settings["policy_version"] << 32) | digest
    jitter = digest % (settings["hard_timeout_jitter_s"] + 1)
    return cookie, settings["normal_hard_timeout_s"] + jitter


class RuleBudget:
    """Conservative normal-rule leases bound tables even if statistics stop."""

    def __init__(self, dpids: list[int], limit: int) -> None:
        self.leases = {dpid: {} for dpid in dpids}
        self.limit = limit

    def admit(self, dpid: int, now: float, lifetime: float, match: dict) -> bool:
        """Reserve distinct matches; replacements renew one conservative lease.

        Match identity includes the whole match, rather than a hash cookie that
        could collide. The bounded scan also supports out-of-order renewals.
        Failed sends retain reservations; disconnects never release them early.
        """
        leases = self.leases[dpid]
        for key in [key for key, expires in leases.items() if expires <= now]:
            del leases[key]
        key = json.dumps(match, sort_keys=True, separators=(",", ":"))
        if key not in leases and len(leases) >= self.limit:
            return False
        leases[key] = max(leases.get(key, 0), now + lifetime)
        return True


class StatsCache:
    """Publish only completed, bounded multipart polls and tag connection generations."""

    def __init__(self, expected: list[int], settings: dict) -> None:
        self.expected = set(expected)
        self.settings = settings
        self.states = {}

    def register(self, dpid: int) -> None:
        """Reset snapshots after reconnect; old counters must not be subtracted."""
        generation = self.states.get(dpid, {}).get("generation", 0) + 1
        self.states[dpid] = {"generation": generation, "connected": True, "pending": None,
                             "snapshot": None, "timeouts": 0, "skipped": 0,
                             "discarded": 0, "polls_completed": 0, "last_error": None}

    def disconnect(self, dpid: int) -> None:
        """Invalidate state without deleting switch rules."""
        if dpid in self.states:
            self.states[dpid]["connected"] = False
            self.states[dpid]["pending"] = None
            self.states[dpid]["snapshot"] = None

    def begin(self, dpid: int, xid: int, now_ns: int) -> bool:
        """Permit one outstanding request per switch and expire missing replies."""
        state = self.states[dpid]
        previous = state["pending"]
        if previous:
            age = (now_ns - previous["requested_ns"]) / 1e9
            if age < self.settings["poll_timeout_s"]:
                state["skipped"] += 1
                return False
            state["timeouts"] += 1
            state["last_error"] = "stats reply timeout"
        state["pending"] = {"xid": xid, "requested_ns": now_ns, "parts": 0, "rows": []}
        return True

    def accept(self, dpid: int, xid: int, rows: list[dict], more: bool, now_ns: int) -> bool:
        """Atomically publish the final part; never expose a partial poll."""
        state = self.states.get(dpid)
        if not state or not state["connected"]:
            return False
        pending = state["pending"]
        if not pending or pending["xid"] != xid:
            state["discarded"] += 1
            return False
        if (now_ns - pending["requested_ns"]) / 1e9 >= self.settings["poll_timeout_s"]:
            state["timeouts"] += 1
            state["last_error"] = "late stats reply"
            state["pending"] = None
            return False
        pending["parts"] += 1
        if (pending["parts"] > self.settings["max_multipart_parts"]
                or len(pending["rows"]) + len(rows) > self.settings["max_rows_per_switch"]):
            state["last_error"] = "multipart statistics exceeded resource limit"
            state["discarded"] += 1
            state["pending"] = None
            return False
        pending["rows"].extend(rows)
        if more:
            return False
        state["polls_completed"] += 1
        state["snapshot"] = {"generation": state["generation"], "poll": state["polls_completed"],
                             "xid": xid, "requested_ns": pending["requested_ns"],
                             "received_ns": now_ns, "rows": pending["rows"]}
        state["pending"] = None
        state["last_error"] = None
        return True

    def reject(self, dpid: int, xid: int, reason: str) -> None:
        """Invalidate an errored stats request without corrupting a newer request."""
        state = self.states.get(dpid)
        if state and state["pending"] and state["pending"]["xid"] == xid:
            state["pending"] = None
            state["last_error"] = reason[:256]

    def view(self, now_ns: int) -> dict:
        """Copy bounded snapshots with explicit age, missing-state and truncation flags."""
        switches = []
        complete = True
        remaining = self.settings["max_api_rows"]
        for dpid in sorted(self.expected):
            state = self.states.get(dpid)
            snapshot = state["snapshot"] if state else None
            age = (now_ns - snapshot["received_ns"]) / 1e9 if snapshot else None
            fresh = bool(state and state["connected"] and snapshot
                         and not state["last_error"] and 0 <= age <= self.settings["max_snapshot_age_s"])
            item = {"dpid": f"{dpid:016x}", "fresh": fresh, "age_s": age,
                    "connected": bool(state and state["connected"]),
                    "error": state["last_error"] if state else "not connected",
                    "timeouts": state["timeouts"] if state else 0,
                    "skipped_polls": state["skipped"] if state else 0,
                    "discarded_parts": state["discarded"] if state else 0,
                    "pending": ({k: state["pending"][k] for k in ("xid", "requested_ns")}
                                if state and state["pending"] else None),
                    "snapshot": None}
            if snapshot:
                take = min(remaining, len(snapshot["rows"]))
                item["snapshot"] = {**snapshot, "rows": copy.deepcopy(snapshot["rows"][:take])}
                remaining -= take
                item["truncated"] = take < len(snapshot["rows"])
                fresh = fresh and not item["truncated"]
            complete = complete and fresh
            switches.append(item)
        return {"complete": complete, "timestamp_ns": now_ns, "switches": switches}
