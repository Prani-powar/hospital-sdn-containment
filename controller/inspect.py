"""Inspect controller health, poll freshness and ingress counter attribution."""
from __future__ import annotations

import argparse
import json
import time

from controller.telemetry_client import ObservationCursor, request_json


def main() -> int:
    """Print bounded health summaries, including measured one-core CPU deltas."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    if not 1 <= args.samples <= 60 or not 0.2 <= args.interval <= 10:
        parser.error("Use 1..60 samples and a 0.2..10 second interval")
    previous = None
    cursor = ObservationCursor()
    healthy = True
    for index in range(args.samples):
        if index:
            time.sleep(args.interval)
        try:
            code, health = request_json(args.base_url, "/v1/health")
            _, stats = request_json(args.base_url, "/v1/stats")
            continuity = cursor.read(stats)
            continuity.pop("new_observations")
            host_rows = {}
            rows = 0
            for switch in stats["switches"]:
                snapshot = switch.get("snapshot")
                for row in snapshot["rows"] if snapshot else []:
                    rows += 1
                    host = row.get("ingress_source_host")
                    if host:
                        host_rows[host] = host_rows.get(host, 0) + 1
            sample = {"check": "controller_sample", "status": health["status"],
                      "controller_epoch": health["controller_epoch"],
                      "connected_switches": len(health["connected_dpids"]),
                      "telemetry_complete": stats["complete"], "reported_flow_rows": rows,
                      "ingress_rows_by_host": host_rows, "counts": health["counts"],
                      "observation_continuity": continuity,
                      "process_max_rss_bytes": health["process_max_rss_bytes"],
                      "process_cpu_s": health["process_cpu_s"],
                      "timestamp_ns": health["timestamp_ns"], "cpu_one_core_percent": None}
            if previous and previous["controller_epoch"] == sample["controller_epoch"]:
                wall = (sample["timestamp_ns"] - previous["timestamp_ns"]) / 1e9
                if wall > 0:
                    sample["cpu_one_core_percent"] = 100 * (
                        sample["process_cpu_s"] - previous["process_cpu_s"]) / wall
            print(json.dumps(sample), flush=True)
            healthy = healthy and code == 200 and stats["complete"]
            previous = sample
        except Exception as exc:
            print(json.dumps({"check": "controller_sample", "status": "ERROR",
                              "error": str(exc)}), flush=True)
            healthy = False
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
