"""Create conservative supervised labels from collector and attack-event JSONL.

Only the known attack source is labelled ``attack`` after its recorded start
time.  Post-attack windows for every other host are deliberately omitted: a
fan-out probe does not prove that those hosts stayed benign.  This keeps
synthetic labels usable for research without converting unknown spread into a
false normal label.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from decision.features import FEATURE_FIELDS

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 200_000_000


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_jsonl(path: Path) -> list[dict]:
    """Read bounded JSONL with deterministic, file-local error locations."""
    _require(path.is_file() and path.stat().st_size <= MAX_FILE_BYTES, f"Invalid input path: {path}")
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON ({exc.msg})") from exc
        _require(isinstance(value, dict), f"{path}:{line_number}: record must be an object")
        rows.append(value)
    return rows


def attack_starts(event_rows: list[dict]) -> dict[str, int]:
    """Return each source's earliest observed harmless attack-process launch."""
    starts: dict[str, int] = {}
    for row in event_rows:
        if row.get("stage") != "attack_start":
            continue
        host, stamp = row.get("host"), row.get("timestamp_ns")
        _require(isinstance(host, str) and host, "attack_start needs a host")
        _require(type(stamp) is int and stamp >= 0, "attack_start needs timestamp_ns")
        starts[host] = min(starts.get(host, stamp), stamp)
    return starts


def annotate(feature_rows: list[dict], event_rows: list[dict], *, normal_only: bool = False) -> tuple[list[dict], dict]:
    """Return ML-pipeline-compatible records and a transparent omission summary."""
    starts = {} if normal_only else attack_starts(event_rows)
    annotated, skipped_invalid, skipped_unknown = [], 0, 0
    for row in feature_rows:
        if row.get("check") != "feature_window":
            continue
        feature, quality = row.get("feature"), row.get("quality")
        if not isinstance(feature, dict) or set(feature) != set(FEATURE_FIELDS):
            skipped_invalid += 1
            continue
        if not isinstance(quality, dict) or quality.get("valid") is not True:
            skipped_invalid += 1
            continue
        host, timestamp = feature.get("host"), feature.get("timestamp_ns")
        if not isinstance(host, str) or type(timestamp) is not int or timestamp < 0:
            skipped_invalid += 1
            continue
        active_sources = {source for source, start in starts.items() if timestamp >= start}
        # Before any attack process starts, all observed source-ingress windows
        # are clean by experiment construction. Once it starts, only the source
        # is known-label evidence; other hosts may be affected and are unknown.
        if not active_sources:
            label = "normal"
            provenance = "pre_attack_window" if starts else "declared_normal_run"
        elif host in active_sources:
            label = "attack"
            provenance = "attack_source_after_recorded_start"
        else:
            skipped_unknown += 1
            continue
        run_id = row.get("run_id")
        _require(isinstance(run_id, str) and run_id, "feature_window needs run_id")
        annotated.append({"run_id": run_id, "label": label, "label_provenance": provenance,
                          "feature": feature, "quality": quality})
    _require(annotated, "No valid labelled windows produced")
    return annotated, {"emitted": len(annotated), "skipped_invalid": skipped_invalid,
                       "skipped_unknown_post_attack": skipped_unknown,
                       "attack_sources": sorted(starts)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True, help="Collector feature JSONL")
    parser.add_argument("--events", type=Path, action="append", default=[], help="Run event JSONL; repeatable")
    parser.add_argument("--normal-only", action="store_true", help="Declare this controlled run clean")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.normal_only and args.events:
        parser.error("Use either --normal-only or --events, not both")
    try:
        features = read_jsonl(args.features)
        events = [row for path in args.events for row in read_jsonl(path)]
        records, summary = annotate(features, events, normal_only=args.normal_only)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, allow_nan=False) + "\n")
        print(json.dumps({"check": "feature_labels_written", "output": str(args.output), **summary}))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"check": "feature_labelling_failed", "error": str(exc)[:512]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
