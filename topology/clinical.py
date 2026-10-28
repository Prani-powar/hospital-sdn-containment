"""Finite, harmless UDP probes for the simulated monitor-to-central service."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Callable
import uuid

import yaml

MAX_PACKET = 1024


def output(check: str, **details: Any) -> None:
    """Emit bounded JSON infrastructure records, not project Event stage records."""
    print(json.dumps({"check": check, "timestamp_ns": time.monotonic_ns(), **details}),
          flush=True)


def load_config(path: Path, topology: dict) -> dict:
    """Validate C1 endpoints and limit traffic volume before creating processes."""
    # Both direct-script and package imports are supported.
    try:
        from .hospital import UniqueKeyLoader
    except ImportError:
        from hospital import UniqueKeyLoader
    if path.stat().st_size > 100_000:
        raise ValueError("Traffic configuration exceeds 100 KB")
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    if not isinstance(c, dict) or c.get("schema_version") != 1 or c.get("flow_id") != "C1":
        raise ValueError("Expected schema_version 1 and flow_id C1")
    hosts = {h["name"]: h for h in topology["hosts"]}
    if c.get("server") not in hosts or hosts[c["server"]]["role"] != "critical_server":
        raise ValueError("C1 server must be a configured critical server")
    sources = c.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
        raise ValueError("Expected 1..8 configured C1 sources")
    if len(set(sources)) != len(sources):
        raise ValueError("Duplicate traffic source")
    if any(s not in hosts or hosts[s]["role"] != "iomt" for s in sources):
        raise ValueError("Every C1 source must be a configured IoMT host")
    for field, low, high in (("udp_port", 1024, 65535), ("rate_hz", 1, 20),
                              ("duration_s", 1, 300), ("startup_timeout_s", 1, 15)):
        if type(c.get(field)) is not int or not low <= c[field] <= high:
            raise ValueError(f"{field} must be an integer in {low}..{high}")
    timeout = c.get("reply_timeout_s")
    if type(timeout) not in (int, float) or not 0 < timeout < 1 / c["rate_hz"]:
        raise ValueError("Reply timeout must be positive and shorter than the probe period")
    c["server_ip"] = str(ipaddress.IPv4Interface(hosts[c["server"]]["ip"]).ip)
    return c


def packet(run_id: str, source: str, sequence: int, sent_ns: int, flow_id: str = "C1") -> bytes:
    """Encode synthetic data with no patient identifiers."""
    body = {"run_id": run_id, "source": source, "seq": sequence,
            "sent_ns": sent_ns, "kind": "synthetic_monitor_probe"}
    if flow_id != "C1":
        body.update(flow_id=flow_id, kind="synthetic_service_probe")
    raw = json.dumps(body).encode()
    if len(raw) > MAX_PACKET:
        raise ValueError("Probe packet too large")
    return raw


def reply_allowed(raw: bytes, allowed_sources: set[str], run_id: str, flow_id: str = "C1") -> bool:
    """Reject malformed, foreign-run or unexpected-source application probes."""
    if len(raw) > MAX_PACKET:
        return False
    try:
        p = json.loads(raw)
        return (isinstance(p, dict) and p.get("run_id") == run_id
                and p.get("source") in allowed_sources
                and p.get("kind") == ("synthetic_monitor_probe" if flow_id == "C1" else "synthetic_service_probe")
                and p.get("flow_id", "C1") == flow_id
                and type(p.get("seq")) is int and p["seq"] > 0
                and type(p.get("sent_ns")) is int and p["sent_ns"] >= 0)
    except (ValueError, TypeError):
        return False


def serve(bind_ip: str, port: int, duration_s: float, run_id: str,
          sources: set[str], ready: Callable[[int], None] | None = None, flow_id: str = "C1") -> None:
    """Echo validated probe packets for a bounded interval."""
    deadline = time.monotonic() + duration_s
    received = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_ip, port))
        sock.settimeout(0.2)
        bound_port = sock.getsockname()[1]
        output(flow_id.lower()+"_server_ready", bind_ip=bind_ip, port=bound_port, run_id=run_id)
        if ready:
            ready(bound_port)
        try:
            while time.monotonic() < deadline:
                try:
                    raw, peer = sock.recvfrom(MAX_PACKET + 1)
                except socket.timeout:
                    continue
                if reply_allowed(raw, sources, run_id, flow_id):
                    sock.sendto(raw, peer)
                    received += 1
        finally:
            output(flow_id.lower()+"_server_stopped", run_id=run_id, accepted_packets=received)


def probe_once(sock: socket.socket, peer: tuple[str, int], raw: bytes,
               timeout_s: float) -> float | None:
    """Return RTT in milliseconds only for an exact matching echo before deadline."""
    start = time.monotonic_ns()
    deadline = time.monotonic() + timeout_s
    sock.sendto(raw, peer)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            reply, sender = sock.recvfrom(MAX_PACKET + 1)
        except socket.timeout:
            return None
        if sender == peer and reply == raw:
            return (time.monotonic_ns() - start) / 1_000_000


def probe(c: dict, source: str, run_id: str) -> None:
    """Send probes without catch-up bursts and emit per-probe plus final metrics."""
    peer = (c["server_ip"], c["udp_port"])
    deadline = time.monotonic() + c["duration_s"]
    attempted = received = 0
    rtt_sum = 0.0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            while time.monotonic() < deadline:
                started = time.monotonic()
                attempted += 1
                rtt = None
                error = None
                try:
                    raw = packet(run_id, source, attempted, time.monotonic_ns(), c.get("flow_id", "C1"))
                    rtt = probe_once(sock, peer, raw, c["reply_timeout_s"])
                except OSError as exc:
                    error = str(exc)
                if rtt is not None:
                    received += 1
                    rtt_sum += rtt
                output(c.get("flow_id", "C1").lower()+"_probe", run_id=run_id, source=source, seq=attempted,
                       success=rtt is not None, rtt_ms=rtt, error=error)
                # Scheduling delay reduces observed rate instead of causing a burst.
                time.sleep(max(0, min(deadline - time.monotonic(),
                                     1 / c["rate_hz"] - (time.monotonic() - started))))
        finally:
            output(c.get("flow_id", "C1").lower()+"_summary", run_id=run_id, source=source, attempted=attempted,
                   received=received, success_rate=received / attempted if attempted else None,
                   mean_rtt_ms=rtt_sum / received if received else None)


class ClinicalTraffic:
    """Own only this run's subprocesses and logs; stop them before network teardown."""

    def __init__(self, net: Any, c: dict, root: Path) -> None:
        self.net, self.config = net, c
        self.run_id = uuid.uuid4().hex
        self.directory = root.resolve() / self.run_id
        self.processes: list[tuple[str, Any]] = []
        self.streams: list[Any] = []

    def spawn(self, host: str, mode: str, config_path: Path) -> Any:
        """Launch the worker in its Mininet namespace with file-backed output."""
        stream = (self.directory / f"{host}.jsonl").open("x")
        self.streams.append(stream)
        command = [sys.executable, "-u", str(Path(__file__).resolve()),
                   mode, "--config", str(config_path), "--source", host,
                   "--run-id", self.run_id]
        worker_environment = dict(os.environ)
        for key in ("HOSPITAL_ACTION_TOKEN", "HOSPITAL_ENABLE_ACTIONS"):
            worker_environment.pop(key, None)
        process = self.net.get(host).popen(command, stdout=stream, stderr=stream, env=worker_environment)
        self.processes.append((host, process))
        return process

    def start(self) -> None:
        """Wait for a bound server before launching clients, or fail with logs."""
        self.directory.mkdir(parents=True, exist_ok=False)
        config_path = self.directory / "run.json"
        config_path.write_text(json.dumps(self.config, indent=2))
        c = self.config
        server = self.spawn(c["server"], "server", config_path)
        log = self.directory / f"{c['server']}.jsonl"
        deadline = time.monotonic() + c["startup_timeout_s"]
        while True:
            if server.poll() is not None:
                raise RuntimeError(f"C1 server exited; inspect {log}")
            lines = log.read_text().splitlines()
            if any(line.startswith("{") and json.loads(line).get("check") == c.get("flow_id", "C1").lower()+"_server_ready"
                   for line in lines):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"C1 server startup timed out; inspect {log}")
            time.sleep(0.05)
        for source in c["sources"]:
            self.spawn(source, "client", config_path)
        output(c.get("flow_id", "C1").lower()+"_started", run_id=self.run_id, logs=str(self.directory),
               duration_s=c["duration_s"], rate_hz=c["rate_hz"], sources=c["sources"])

    def stop(self) -> None:
        """Terminate only owned workers, wait with bounds, close every log stream."""
        for _, p in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
        try:
            for host, p in reversed(self.processes):
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=2)
                output("c1_worker_stopped", host=host, returncode=p.returncode)
        finally:
            for stream in self.streams:
                stream.close()


def status(root: Path) -> None:
    """Summarize the latest run without counting client startup as successful traffic."""
    paths = [p for p in root.glob("*/run.json") if p.is_file()]
    if not paths:
        raise ValueError("No C1 runs found")
    latest = max(paths, key=lambda p: p.stat().st_mtime_ns)
    c = json.loads(latest.read_text())
    for source in c["sources"]:
        attempted = received = 0
        rtt_sum = 0.0
        path = latest.parent / f"{source}.jsonl"
        for line in path.read_text().splitlines() if path.exists() else []:
            try:
                p = json.loads(line)
            except ValueError:  # A live writer may not have completed its last line.
                continue
            if p.get("check") == "c1_probe":
                attempted += 1
                if p["success"]:
                    received += 1
                    rtt_sum += p["rtt_ms"]
        output("c1_status", run_id=latest.parent.name, source=source, attempted=attempted,
               received=received, success_rate=received / attempted if attempted else None,
               mean_rtt_ms=rtt_sum / received if received else None)


def main() -> int:
    """Worker entrypoint and unprivileged latest-run status command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client", "status"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--run-id")
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "artifacts" / "clinical")
    args = parser.parse_args()

    def terminate(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    try:
        if args.mode == "status":
            status(args.root)
            return 0
        if not args.config or not args.source or not args.run_id:
            raise ValueError("Workers require --config, --source and --run-id")
        c = json.loads(args.config.read_text())
        if args.mode == "server":
            serve(c["server_ip"], c["udp_port"], c["duration_s"] + c["startup_timeout_s"],
                  args.run_id, set(c["sources"]), flow_id=c.get("flow_id", "C1"))
        else:
            probe(c, args.source, args.run_id)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        output("c1_error", error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
