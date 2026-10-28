"""Repeatable C1 preservation test using scoped OVS rules, not a policy engine."""
from __future__ import annotations

from collections import defaultdict, deque
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any

import yaml

try:
    from .hospital import UniqueKeyLoader, emit, require
except ImportError:
    from hospital import UniqueKeyLoader, emit, require

ALLOW_BASE = 0xC100000000000000
DROP_COOKIE = 0xC140000000000001
COOKIE_MASK = 0xFFFF000000000000


def load_config(path: Path, topology: dict, traffic: dict | None) -> dict:
    """Validate the demo and leave enough traffic duration for its three phases."""
    require(traffic is not None, "Restriction demo requires --traffic")
    require(path.stat().st_size <= 100_000, "Demo configuration exceeds 100 KB")
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(c, dict) and c.get("schema_version") == 1, "Invalid demo schema")
    hosts = {h["name"]: h for h in topology["hosts"]}
    require(c.get("target") in traffic["sources"], "Target must be a configured C1 source")
    require(hosts[c["target"]]["role"] == "iomt", "This demo restricts an IoMT source only")
    require(c.get("blocked_peer") in hosts and c["blocked_peer"] != c["target"],
            "Invalid ping-control peer")
    for field, low, high in (("warmup_s", 1, 5), ("phase_s", 2, 5),
                             ("quarantine_timeout_s", 8, 20), ("expiry_grace_s", 1, 10),
                             ("minimum_probes", 1, 100)):
        require(type(c.get(field)) is int and low <= c[field] <= high,
                f"{field} must be an integer in {low}..{high}")
    require(c["phase_s"] + 3 < c["quarantine_timeout_s"],
            "Restriction phase must finish well before the drop expires")
    rate = c.get("minimum_success_rate")
    require(type(rate) in (int, float) and 0 < rate <= 1,
            "minimum_success_rate must be in (0, 1]")
    require(c["minimum_probes"] <= traffic["rate_hz"] * c["phase_s"],
            "Minimum probe count exceeds the nominal phase count")
    budget = c["warmup_s"] + c["quarantine_timeout_s"] + c["expiry_grace_s"] + 2 * c["phase_s"] + 15
    require(traffic["duration_s"] >= budget,
            f"Traffic duration must be at least {budget}s for this demo")
    return c


def route(topology: dict, source: str, destination: str) -> list[tuple[str, int]]:
    """Compute each switch's output port along the configured loop-free path."""
    adjacent = defaultdict(list)
    for link in topology["links"]:
        adjacent[link["node1"]].append((link["node2"], link["port1"]))
        adjacent[link["node2"]].append((link["node1"], link["port2"]))
    queue = deque([(source, [])])
    seen = {source}
    switch_names = {s["name"] for s in topology["switches"]}
    while queue:
        node, path = queue.popleft()
        if node == destination:
            return path
        for peer, port in adjacent[node]:
            if peer not in seen:
                seen.add(peer)
                queue.append((peer, path + ([(node, port)] if node in switch_names else [])))
    raise ValueError(f"No route from {source} to {destination}")


def critical_rules(topology: dict, traffic: dict) -> dict[str, list[str]]:
    """Generate specific request/reply allows on every traversed switch."""
    hosts = {h["name"]: h for h in topology["hosts"]}
    groups: dict[str, list[str]] = defaultdict(list)
    sequence = 0
    for source in traffic["sources"]:
        for src, dst, field in ((source, traffic["server"], "tp_dst"),
                                 (traffic["server"], source, "tp_src")):
            src_ip = str(ipaddress.IPv4Interface(hosts[src]["ip"]).ip)
            dst_ip = str(ipaddress.IPv4Interface(hosts[dst]["ip"]).ip)
            for switch, port in route(topology, src, dst):
                sequence += 1
                groups[switch].append(
                    f"cookie=0x{ALLOW_BASE + sequence:x},priority=50000,udp,"
                    f"nw_src={src_ip},nw_dst={dst_ip},{field}={traffic['udp_port']},"
                    f"actions=output:{port}")
    return dict(groups)


def drop_rule(topology: dict, config: dict) -> tuple[str, str]:
    """Restrict outbound IPv4 at ingress; C1 allows retain higher priority."""
    host = next(h for h in topology["hosts"] if h["name"] == config["target"])
    ip = str(ipaddress.IPv4Interface(host["ip"]).ip)
    return host["switch"], (
        f"cookie=0x{DROP_COOKIE:x},priority=40000,ip,nw_src={ip},"
        f"hard_timeout={config['quarantine_timeout_s']},actions=drop")


def ofctl(*args: str, stdin: str | None = None) -> str:
    """Use bounded, shell-free OVS commands and report failures verbatim."""
    result = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", *args], input=stdin,
                            capture_output=True, text=True, timeout=4)
    if result.returncode:
        raise RuntimeError(f"ovs-ofctl {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def cookie_records(text: str, cookie: int) -> list[str]:
    """Select exact cookies rather than matching a substring or a header."""
    return [line for line in text.splitlines()
            if (match := re.search(r"\bcookie=0x([0-9a-fA-F]+)\b", line))
            and int(match.group(1), 16) == cookie]


def samples(path: Path, start_ns: int, end_ns: int) -> dict:
    """Count only completed probes inside the named monotonic measurement window."""
    attempted = received = 0
    rtt_sum = 0.0
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if (record.get("check") == "c1_probe"
                and start_ns <= record["timestamp_ns"] < end_ns):
            attempted += 1
            if record["success"]:
                received += 1
                rtt_sum += record["rtt_ms"]
    return {"attempted": attempted, "received": received,
            "success_rate": received / attempted if attempted else None,
            "mean_rtt_ms": rtt_sum / received if received else None}


def workers_live(manager: Any) -> None:
    """Reject expired or crashed traffic workers instead of reading stale success."""
    require(all(process.poll() is None for _, process in manager.processes),
            "A traffic worker stopped early; inspect this run's logs")


def run(net: Any, topology: dict, traffic: dict, manager: Any, config: dict) -> dict:
    """Run baseline/restricted/recovered phases and persist evidence even on failure."""
    report: dict = {"run_id": manager.run_id, "variant": "C1-functional-rule-test",
                    "target": config["target"], "phases": [], "passed": False}
    report_path = manager.directory / "restriction-report.json"
    host_ips = {h["name"]: str(ipaddress.IPv4Interface(h["ip"]).ip)
                for h in topology["hosts"]}
    switch, drop = drop_rule(topology, config)
    cookie_filter = f"cookie=0x{DROP_COOKIE:x}/-1"

    def read_drop() -> list[str]:
        return cookie_records(ofctl("dump-flows", switch, cookie_filter), DROP_COOKIE)

    def phase(name: str, ping_should_pass: bool) -> None:
        workers_live(manager)
        start = time.monotonic_ns()
        stdout, stderr, code = net.get(config["target"]).pexec([
            "ping", "-c", "2", "-W", "1", host_ips[config["blocked_peer"]]])
        time.sleep(config["phase_s"])
        end = time.monotonic_ns()
        workers_live(manager)
        health = {source: samples(manager.directory / f"{source}.jsonl", start, end)
                  for source in traffic["sources"]}
        record = {"phase": name, "start_ns": start, "end_ns": end,
                  "ping_exit_code": code, "ping_output": stdout + stderr,
                  "monitors": health}
        if name == "restricted":
            rows = read_drop()
            record["drop_rules"] = rows
            counters = [int(m.group(1)) for row in rows
                        if (m := re.search(r"\bn_packets=(\d+)\b", row))]
            record["drop_packets"] = sum(counters)
        report["phases"].append(record)
        emit("restriction_phase", **record)
        # ping code 2 means command/network error, not evidence of deliberate blocking.
        require(code == (0 if ping_should_pass else 1),
                f"{name}: unexpected ping exit status {code}")
        for source, result in health.items():
            require(result["attempted"] >= config["minimum_probes"],
                    f"{name}: insufficient fresh probes from {source}")
            require(result["success_rate"] >= config["minimum_success_rate"],
                    f"{name}: C1 success rate too low for {source}")
        if name == "restricted":
            require(len(record["drop_rules"]) == 1 and record["drop_packets"] >= 2,
                    "No active drop rule with at least two matched packets")

    try:
        # Make-before-break: install and read back all allows before adding a drop.
        for bridge, rules in critical_rules(topology, traffic).items():
            ofctl("add-flows", bridge, "-", stdin="\n".join(rules) + "\n")
            installed = ofctl("dump-flows", bridge,
                              f"cookie=0x{ALLOW_BASE:x}/0x{COOKIE_MASK:x}")
            for rule in rules:
                cookie = int(re.search(r"cookie=0x([0-9a-f]+)", rule).group(1), 16)
                rows = cookie_records(installed, cookie)
                require(len(rows) == 1 and "priority=50000" in rows[0],
                        f"Critical allow not confirmed on {bridge}")
        emit("c1_allows_confirmed")
        time.sleep(config["warmup_s"])
        phase("before", True)
        ofctl("add-flow", switch, drop)
        require(len(read_drop()) == 1, "Ingress restriction was not installed")
        report["drop_confirmed_ns"] = time.monotonic_ns()
        phase("restricted", False)
        deadline = time.monotonic() + config["quarantine_timeout_s"] + config["expiry_grace_s"]
        while read_drop():
            require(time.monotonic() < deadline, "Drop did not expire within deadline")
            time.sleep(0.2)
        report["expiry_observed_ns"] = time.monotonic_ns()
        phase("recovered", True)
        report["passed"] = True
        emit("restriction_demo", status="PASS", report=str(report_path), run_id=manager.run_id)
        return report
    except Exception as exc:
        report["error"] = str(exc)
        emit("restriction_demo", status="FAIL", error=str(exc), report=str(report_path))
        raise
    finally:
        # No delete API for protected allows. The enclosing launcher tears down
        # the disposable network; any remaining drop has a hard timeout.
        report_path.write_text(json.dumps(report, indent=2) + "\n")
