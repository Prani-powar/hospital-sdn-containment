"""Finite read-only feature collector; runs separately from the Ryu container."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import time
import uuid

from controller.telemetry_client import TelemetryClient
from decision.features import from_files

ROOT = Path(__file__).resolve().parents[1]


def event(run_id: str, stage: str, host: str | None, details: dict) -> dict:
    """Preserve the agreed Event fields and monotonic stage timestamps."""
    return {"run_id": run_id, "timestamp_ns": time.monotonic_ns(),
            "stage": stage, "host": host, "details": details}


async def collect(args: argparse.Namespace) -> int:
    """One coroutine owns all extraction state; HTTP work uses bounded executor slots."""
    extractor = from_files(args.topology, args.config)
    run_id = uuid.uuid4().hex
    output = args.output or ROOT / "artifacts" / "features" / f"{run_id}.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents silently overwriting an earlier dataset.
    client = TelemetryClient(args.base_url, concurrency=1)
    statuses, windows, latest = Counter(), Counter(), {}
    provenance = {"config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
                  "topology_sha256": hashlib.sha256(args.topology.read_bytes()).hexdigest(),
                  "feature_spec_version": "source-ingress-proxy-v1"}
    print(json.dumps({"check": "features_started", "run_id": run_id,
                      "output": str(output), "samples": args.samples, **provenance}), flush=True)
    with output.open("x", encoding="utf-8") as stream:
        def write(record: dict) -> None:
            stream.write(json.dumps(record, allow_nan=False) + "\n")
            stream.flush()

        write({"check": "features_metadata", "run_id": run_id, **provenance,
               "config": extractor.config, "topology_name": extractor.fabric.topology["name"]})
        for index in range(args.samples):
            tick = time.monotonic()
            try:
                body = await client.get_stats(require_complete=False)
                received = time.monotonic_ns()
                write(event(run_id, "poll_received", None, {
                    "controller_epoch": body.get("controller_epoch"),
                    "controller_snapshot_ns": body.get("timestamp_ns"),
                    "flow_snapshot_complete": body.get("complete")}))
                result = extractor.ingest(body, received)
            except Exception as exc:
                result = extractor.invalidate("http_read_failed")
                write({"check": "feature_collection_error", "run_id": run_id,
                       "timestamp_ns": time.monotonic_ns(), "error": str(exc)[:256]})
            statuses[result["status"]] += 1
            if result["status"] != "ready":
                write({"check": "feature_quality", "run_id": run_id,
                       "timestamp_ns": time.monotonic_ns(), **result})
            for feature in result["features"]:
                write(event(run_id, "features_ready", feature["host"], {
                    "window_end_ns": feature["timestamp_ns"], "window_s": feature["window_s"]}))
                write({"check": "feature_window", "run_id": run_id, "feature": feature,
                       "quality": result["quality"], "derived": {
                           "rule_hit_packets_out_per_s": feature["pkts_out"] / feature["window_s"],
                           "rule_hit_bytes_out_per_s": feature["bytes_out"] / feature["window_s"]}})
                windows[feature["host"]] += 1
                latest[feature["host"]] = feature
            if index + 1 < args.samples:
                await asyncio.sleep(max(0, extractor.config["poll_interval_s"] -
                                        (time.monotonic() - tick)))
    summary = {"check": "features_summary", "run_id": run_id, "output": str(output),
               **provenance,
               "sample_statuses": dict(statuses), "invalid_reasons": dict(extractor.skips),
               "windows_by_host": dict(windows),
               "latest_features": [latest[h] for h in extractor.config["summary_hosts"] if h in latest]}
    print(json.dumps(summary, allow_nan=False), flush=True)
    return 0 if windows else 1


def main() -> int:
    """Collect a bounded dataset; no model, action API, threads or SQLite writer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, default=ROOT / "configs" / "hospital.yaml")
    parser.add_argument("--config", type=Path, default=ROOT / "configs" / "features.yaml")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 2 <= args.samples <= 3600:
        parser.error("Use 2..3600 samples")
    try:
        return asyncio.run(collect(args))
    except (OSError, ValueError) as exc:
        print(json.dumps({"check": "features_failed", "error": str(exc)[:256]}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
