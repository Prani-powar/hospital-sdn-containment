"""Run the actual detector/planner against recorded features or explicit synthetic fixtures."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import time
from typing import Iterator
import uuid

from decision.detection import from_config

ROOT = Path(__file__).resolve().parents[1]


def demo_records(engine: object) -> Iterator[dict]:
    """Generate labelled fixtures, never fabricated measurements from a real network."""
    quality = {"valid": True, "feature_spec_version": engine.config["feature_spec_version"],
               "profile_version": engine.config["profile_version"]}
    for index in range(9):
        stamp = (index + 1) * 1_000_000_000
        yield {"stage": "poll_received", "details": {"controller_epoch": "synthetic-fixture"}}
        for name in engine.config["demo_hosts"]:
            role = engine.fabric.hosts[name]["role"]
            t = engine.config["thresholds"][role]
            suspect = index < 6
            destinations, ports = (t["unique_dst"], t["unique_dst_ports"]) if suspect else (1, 1)
            feature = {"timestamp_ns": stamp, "window_s": 5, "host": name, "role": role,
                "flow_count": max(destinations, ports), "unique_dst": destinations,
                "unique_dst_ports": ports, "bytes_in": 0, "bytes_out": 10000,
                "pkts_in": 0, "pkts_out": 100, "new_peers": destinations,
                "off_allow_list_flows": 2 if suspect else 0, "short_flows": 0}
            yield {"check": "feature_window", "quality": quality, "feature": feature}


def replay(records: Iterator[dict], engine: object, emit: object) -> dict:
    """Use evidence timestamps for offline leases and actual process time for Event stages."""
    run_id = uuid.uuid4().hex
    epoch = None
    latest = -1
    counts, actions = Counter(), Counter()

    def publish(proposal: dict) -> None:
        actions[proposal["action"]["action"]] += 1
        emit({"run_id": run_id, "timestamp_ns": time.monotonic_ns(), "stage": "decision",
              "host": proposal["action"]["host"], "details": {
                  "mode": "offline_replay", "proposal": proposal, "applied": False}})

    for record in records:
        if record.get("stage") == "poll_received":
            candidate = record.get("details", {}).get("controller_epoch")
            if isinstance(candidate, str):
                epoch = candidate
            continue
        if record.get("check") == "feature_quality":
            if record.get("status") in ("invalid", "baseline"):
                engine.invalidate()
            continue
        if record.get("check") != "feature_window":
            continue
        f = record.get("feature", {})
        stamp = f.get("timestamp_ns")
        if type(stamp) is not int or stamp < latest:
            engine.invalidate()
            counts["nonmonotonic_record"] += 1
            continue
        latest = stamp
        for proposal in engine.tick(stamp):
            publish(proposal)
        result = engine.consume(f, record.get("quality", {}), stamp, epoch)
        counts[result["status"]] += 1
        if result["score"] is not None:
            emit({"run_id": run_id, "timestamp_ns": time.monotonic_ns(), "stage": "scored",
                  "host": f["host"], "details": {"mode": "offline_replay",
                      "evidence_timestamp_ns": stamp, "score": result["score"],
                      "desired_state": result.get("desired_state"), "applied": False}})
        for proposal in result["proposals"]:
            publish(proposal)
    return {"check": "detection_replay_summary", "run_id": run_id,
            "mode": "offline_replay", "sample_statuses": dict(counts),
            "proposed_actions": dict(actions), "network_actions_sent": 0}


def read_records(path: Path) -> Iterator[dict]:
    """Bound input size/count and reject malformed JSONL rather than skipping bad evidence."""
    if path.stat().st_size > 200 * 1024 * 1024:
        raise ValueError('Feature file exceeds 200 MB')
    with path.open(encoding='utf-8') as stream:
        for index, line in enumerate(stream):
            if index >= 100_000 or len(line) > 1_000_000:
                raise ValueError('Feature input record limit exceeded')
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError('Expected JSON objects')
            yield value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--input', type=Path)
    choice.add_argument('--demo', action='store_true')
    parser.add_argument('--summary-only', action='store_true')
    parser.add_argument('--topology', type=Path, default=ROOT/'configs'/'hospital.yaml')
    parser.add_argument('--config', type=Path, default=ROOT/'configs'/'detection.yaml')
    args = parser.parse_args()
    try:
        engine = from_config(args.topology, args.config)
        records = demo_records(engine) if args.demo else read_records(args.input)
        emit = (lambda value: None) if args.summary_only else (lambda value: print(json.dumps(value)))
        summary = replay(records, engine, emit)
        summary['synthetic_input'] = args.demo
        print(json.dumps(summary, allow_nan=False))
        return 0 if summary['sample_statuses'].get('scored', 0) else 1
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps({'check': 'detection_replay_error', 'error': str(exc)[:256]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
