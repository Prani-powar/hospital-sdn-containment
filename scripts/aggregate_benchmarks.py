"""Aggregate measured B0-B3 experiment records with per-group 95% intervals."""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

BASELINES = {"B0", "B1", "B2", "B3"}
SCENARIOS = {"S1", "S2", "S3"}
METRICS = ("detection_delay_s", "enforcement_delay_s", "time_to_contain_s",
           "hosts_infected_before_containment", "critical_flow_success_rate",
           "critical_flow_mean_rtt_ms", "false_positive_rate", "precision", "recall", "f1",
           "controller_cpu_percent", "controller_memory_mb", "rule_count")
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
        8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
        15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
        27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042}


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def read_records(path: Path) -> list[dict]:
    _require(path.is_file() and path.stat().st_size <= 100_000_000, "Invalid benchmark input")
    values = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON") from exc
        _require(isinstance(row, dict) and row.get("schema_version") == 1, f"{path}:{number}: invalid schema")
        _require(row.get("baseline") in BASELINES and row.get("scenario") in SCENARIOS,
                 f"{path}:{number}: unknown baseline/scenario")
        _require(type(row.get("seed")) is int and row["seed"] >= 0 and isinstance(row.get("run_id"), str),
                 f"{path}:{number}: invalid run identity")
        _require(row.get("evidence_status") == "PASS", f"{path}:{number}: only reassessed PASS runs may aggregate")
        _require(row.get("false_isolation_critical") is False, f"{path}:{number}: critical-device safety failure")
        metrics = row.get("metrics")
        _require(isinstance(metrics, dict), f"{path}:{number}: missing metrics")
        for name, value in metrics.items():
            _require(name in METRICS and type(value) in (int, float) and math.isfinite(value) and value >= 0,
                     f"{path}:{number}: invalid metric")
        values.append(row)
    _require(values, "No benchmark records")
    return values


def mean_ci(values: list[float]) -> dict:
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return {"n": n, "mean": mean, "ci95_half_width": None}
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    critical = T975.get(n - 1, 1.96)
    return {"n": n, "mean": mean, "ci95_half_width": critical * math.sqrt(variance / n)}


def aggregate(records: list[dict], minimum_runs: int = 10) -> dict:
    _require(type(minimum_runs) is int and 2 <= minimum_runs <= 1000, "Invalid minimum runs")
    groups: dict[tuple, list[dict]] = defaultdict(list)
    identities = set()
    for record in records:
        key = record["baseline"], record["scenario"], record["seed"]
        _require(key not in identities, "Duplicate baseline/scenario/seed record")
        identities.add(key)
        groups[key[:2]].append(record)
    summary = []
    for (baseline, scenario), rows in sorted(groups.items()):
        by_metric = {metric: mean_ci([r["metrics"][metric] for r in rows if metric in r["metrics"]])
                     for metric in METRICS if any(metric in r["metrics"] for r in rows)}
        summary.append({"baseline": baseline, "scenario": scenario, "runs": len(rows),
                        "required_runs": minimum_runs, "coverage_complete": len(rows) >= minimum_runs,
                        "seeds": sorted(r["seed"] for r in rows), "metrics": by_metric})
    return {"schema_version": 1, "groups": summary,
            "complete_matrix": all(any(g["baseline"] == b and g["scenario"] == s and g["coverage_complete"]
                                        for g in summary) for b in BASELINES for s in SCENARIOS),
            "note": "95% intervals use Student t by seed; missing metrics remain absent, never zero."}


def export(result: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    (output / "benchmark_summary.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    with (output / "benchmark_summary.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["baseline", "scenario", "runs", "coverage_complete", "metric", "mean", "ci95_half_width"])
        writer.writeheader()
        for group in result["groups"]:
            for metric, value in group["metrics"].items():
                writer.writerow({**{k: group[k] for k in ("baseline", "scenario", "runs", "coverage_complete")},
                                 "metric": metric, "mean": value["mean"], "ci95_half_width": value["ci95_half_width"]})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="One JSONL record per completed lab run")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--minimum-runs", type=int, default=10)
    args = parser.parse_args()
    try:
        result = aggregate(read_records(args.input), args.minimum_runs)
        export(result, args.output)
        print(json.dumps({"check": "benchmark_aggregated", "complete_matrix": result["complete_matrix"], "output": str(args.output)}))
        return 0 if result["complete_matrix"] else 2
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"check": "benchmark_aggregation_failed", "error": str(exc)[:256]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
