"""Bounded harmless UDP load inside one configured Mininet host, without spreading."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import time

from topology.hospital import load_plan


def main() -> int:
    """Send a finite load to configured lab peers; binding prevents ordinary host use."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--rate", type=int, default=500)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--config", type=Path,
                        default=Path(__file__).resolve().parents[1] / "configs" / "hospital.yaml")
    args = parser.parse_args()
    if not 1 <= args.rate <= 2000 or not 1 <= args.duration <= 30:
        parser.error("Rate must be 1..2000 packets/s and duration 1..30 seconds")
    plan = load_plan(args.config)
    hosts = {h["name"]: str(ipaddress.IPv4Interface(h["ip"]).ip) for h in plan["hosts"]}
    if args.host not in hosts:
        parser.error("Source host must exist in the hospital configuration")
    peers = [ip for name, ip in hosts.items() if name != args.host]
    count = errors = 0
    start = time.monotonic()
    deadline = start + args.duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((hosts[args.host], 0))
        while time.monotonic() < deadline:
            tick = time.monotonic()
            try:
                sock.sendto(b"harmless-sdn-load-probe",
                            (peers[count % len(peers)], 20000 + count % 20000))
            except OSError:
                errors += 1
            count += 1
            time.sleep(max(0, 1 / args.rate - (time.monotonic() - tick)))
    elapsed = time.monotonic() - start
    print(json.dumps({"check": "storm_probe_finished", "host": args.host,
                      "attempted": count, "send_errors": errors, "elapsed_s": elapsed,
                      "offered_packets_per_s": count / elapsed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
