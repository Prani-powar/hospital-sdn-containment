"""Offline M1/M2 training and evaluation for labelled feature-window datasets.

This module is deliberately not imported by ``decision.live`` or the policy
planner.  It reads saved measurements, writes versioned artefacts, and cannot
contact the controller or install a rule.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

import joblib
import matplotlib
matplotlib.use("Agg")  # Headless lab/container-safe plot rendering.
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (average_precision_score, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from decision.features import FEATURE_FIELDS

ROOT = Path(__file__).resolve().parents[1]
FEATURE_VERSION = "source-ingress-proxy-v1"
# Timestamp identifies a collection cut, while host/role identify the lab
# inventory.  Neither belongs in a learned behavioural vector.
MODEL_FIELDS = ("flow_count", "unique_dst", "unique_dst_ports", "bytes_in", "bytes_out",
                "pkts_in", "pkts_out", "new_peers", "off_allow_list_flows", "short_flows")
ROLES = {"admin", "clinical", "critical_server", "iomt", "guest", "vendor"}


def _fail(message: str) -> None:
    raise ValueError(message)


def _label(value: object, source: Path, line: int) -> int:
    if value in (0, "0", "normal", "benign"):
        return 0
    if value in (1, "1", "attack", "anomalous", "malicious"):
        return 1
    _fail(f"{source}:{line}: label must be normal/attack or 0/1")


def read_windows(paths: list[Path], *, require_label: bool, default_label: int | None = None) -> list[dict]:
    """Read collector JSONL or an annotated copy without accepting invalid samples.

    A training row may be a collector ``feature_window`` record or a compact
    ``{feature, quality, label, run_id}`` record.  The run identifier is used
    as the split group so overlapping windows never leak across train/test.
    """
    rows = []
    for path in paths:
        if not path.is_file() or path.stat().st_size > 200_000_000:
            _fail(f"Invalid dataset path: {path}")
        for line_no, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not text.strip():
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                _fail(f"{path}:{line_no}: invalid JSON ({exc.msg})")
            if not isinstance(record, dict):
                _fail(f"{path}:{line_no}: record must be an object")
            if record.get("check") not in (None, "feature_window") and "feature" not in record:
                continue
            feature = record.get("feature", record)
            quality = record.get("quality")
            if not isinstance(feature, dict) or set(feature) != set(FEATURE_FIELDS):
                _fail(f"{path}:{line_no}: Feature contract mismatch")
            if not isinstance(quality, dict) or quality.get("valid") is not True or quality.get("feature_spec_version") != FEATURE_VERSION:
                _fail(f"{path}:{line_no}: only valid {FEATURE_VERSION} windows may train a model")
            if not all(type(feature[name]) is int and feature[name] >= 0 for name in MODEL_FIELDS):
                _fail(f"{path}:{line_no}: invalid numeric feature")
            if feature.get("role") not in ROLES:
                _fail(f"{path}:{line_no}: unknown role")
            label_value = record.get("label", default_label)
            if require_label and label_value is None:
                _fail(f"{path}:{line_no}: missing label")
            label = _label(label_value, path, line_no) if label_value is not None else None
            run_id = record.get("run_id")
            if not isinstance(run_id, str) or not run_id:
                # A file is one run when collector data has no explicit run id.
                run_id = path.stem
            rows.append({"x": [feature[name] for name in MODEL_FIELDS], "role": feature["role"], "label": label,
                         "run_id": run_id, "source": str(path), "seed": record.get("seed"), "partition": record.get("partition")})
    if not rows:
        _fail("No valid feature windows found")
    return rows


def _group_split(rows: list[dict], test_size: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    labels = np.array([r["label"] for r in rows], dtype=int)
    groups = np.array([r["run_id"] for r in rows])
    if set(labels) != {0, 1}:
        _fail("Labelled data needs both normal and attack windows")
    class_groups = {label: set(groups[labels == label]) for label in (0, 1)}
    if min(map(len, class_groups.values())) < 2:
        _fail("Need at least two distinct run_id values for each class to avoid run leakage")
    splitter = GroupShuffleSplit(n_splits=32, test_size=test_size, random_state=seed)
    for train, test in splitter.split(np.zeros(len(rows)), labels, groups):
        if set(labels[train]) == {0, 1} and set(labels[test]) == {0, 1}:
            return train, test
    _fail("Unable to create a class-complete group holdout split")


def _metrics(y: np.ndarray, scores: np.ndarray, predicted: np.ndarray) -> dict:
    return {"roc_auc": float(roc_auc_score(y, scores)),
            "average_precision": float(average_precision_score(y, scores)),
            "f1": float(f1_score(y, predicted, zero_division=0)),
            "precision": float(precision_score(y, predicted, zero_division=0)),
            "recall": float(recall_score(y, predicted, zero_division=0))}


def _plot(y: np.ndarray, scored: dict[str, np.ndarray], output: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for name, scores in scored.items():
        fpr, tpr, _ = roc_curve(y, scores)
        precision, recall, _ = precision_recall_curve(y, scores)
        axes[0].plot(fpr, tpr, label=name)
        axes[1].plot(recall, precision, label=name)
    axes[0].plot([0, 1], [0, 1], "k--", linewidth=1)
    axes[0].set(xlabel="False-positive rate", ylabel="True-positive rate", title="ROC")
    axes[1].set(xlabel="Recall", ylabel="Precision", title="Precision–recall")
    for axis in axes:
        axis.legend()
        axis.grid(alpha=.25)
    fig.tight_layout()
    fig.savefig(output, dpi=160)
    plt.close(fig)


def train(normal_paths: list[Path], labelled_paths: list[Path], output: Path, *, seed: int = 42,
          test_size: float = .25, contamination: float = .05, split_manifest: dict | None = None) -> dict:
    """Fit M1 on clean windows and M2 on labelled runs, then evaluate one holdout."""
    if not 0 < test_size < .5 or not 0 < contamination < .5:
        _fail("test_size and contamination must be between 0 and 0.5")
    normal = read_windows(normal_paths, require_label=False, default_label=0)
    if any(row["label"] != 0 for row in normal):
        _fail("--normal input may contain only normal labels")
    labelled = read_windows(labelled_paths, require_label=True)
    validation_idx = []
    if split_manifest is None:
        train_idx, test_idx = _group_split(labelled, test_size, seed)
    else:
        if set(split_manifest) != {'train_runs','validation_runs','test_runs'}:
            _fail('Split manifest needs train_runs, validation_runs, test_runs')
        groups = [set(split_manifest[k]) for k in ('train_runs','validation_runs','test_runs')]
        if any(not g for g in groups) or any(groups[i] & groups[j] for i in range(3) for j in range(i)):
            _fail('Split run sets must be nonempty and disjoint')
        if set(r['run_id'] for r in labelled) != set.union(*groups):
            _fail('Manifest must cover exactly the labelled run inventory')
        train_idx, validation_idx, test_idx = [np.array([i for i,r in enumerate(labelled) if r['run_id'] in g],dtype=int) for g in groups]
        for indices in (train_idx, validation_idx, test_idx):
            if {labelled[i]['label'] for i in indices} != {0,1}:
                _fail('Each run split needs normal and attack labels')
    fitting_rows = normal + [labelled[i] for i in train_idx]
    if any(r.get('partition') == 'test' for r in fitting_rows):
        _fail('Held-out experiment seeds cannot enter model fitting')
    held_out = {labelled[i]['run_id'] for i in list(validation_idx) + list(test_idx)}
    if any(r['run_id'] in held_out for r in normal):
        _fail('Normal-fit input overlaps validation/test runs')
    x_labelled = np.asarray([r["x"] for r in labelled], dtype=float)
    y = np.asarray([r["label"] for r in labelled], dtype=int)
    x_train, x_test, y_train, y_test = x_labelled[train_idx], x_labelled[test_idx], y[train_idx], y[test_idx]
    # M1 has a baseline per role.  Test rows never contribute to a role's model
    # or calibration distribution, and every role observed in the labelled set
    # needs enough clean evidence for a defensible baseline.
    clean_by_role = {role: [r["x"] for r in normal if r["role"] == role] +
                     [labelled[i]["x"] for i in train_idx if y[i] == 0 and labelled[i]["role"] == role]
                     for role in {r["role"] for r in normal + labelled}}
    missing = sorted(role for role in {r["role"] for r in labelled} if len(clean_by_role[role]) < 20)
    if missing:
        _fail("Need at least 20 normal training windows for each labelled role: " + ", ".join(missing))
    m1_models, m1_thresholds, m1_calibration = {}, {}, {}
    for role, vectors in clean_by_role.items():
        if len(vectors) < 20:
            continue
        model = Pipeline([("scale", StandardScaler()), ("model", IsolationForest(
            n_estimators=200, contamination=contamination, random_state=seed, n_jobs=1))])
        x_clean = np.asarray(vectors, dtype=float)
        model.fit(x_clean)
        calibration_vectors = [labelled[i]['x'] for i in validation_idx
                               if labelled[i]['label'] == 0 and labelled[i]['role'] == role]
        if split_manifest is not None and not calibration_vectors:
            _fail('Validation split needs normal calibration windows for role: ' + role)
        calibration = np.sort(-model.decision_function(np.asarray(calibration_vectors) if calibration_vectors else x_clean))
        m1_models[role] = model
        m1_calibration[role] = calibration
        m1_thresholds[role] = float(np.quantile(calibration, 1 - contamination))
    test_roles = [labelled[i]["role"] for i in test_idx]
    m1_scores = np.asarray([np.searchsorted(m1_calibration[role], -m1_models[role].decision_function([x])[0], side="right") /
                            len(m1_calibration[role]) for x, role in zip(x_test, test_roles)])
    m1_predicted = m1_scores >= 1 - contamination
    m2 = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=1)
    m2.fit(x_train, y_train)
    m2_threshold = .5
    if len(validation_idx):
        val_scores = m2.predict_proba(x_labelled[validation_idx])[:,1]
        candidates = (.25,.5,.75)
        m2_threshold = max(candidates, key=lambda t: (f1_score(y[validation_idx],val_scores >= t,zero_division=0), -abs(t-.5)))
    m2_scores = m2.predict_proba(x_test)[:, 1]
    output.mkdir(parents=True, exist_ok=False)
    joblib.dump({"schema_version": 1, "feature_spec_version": FEATURE_VERSION,
                 "model_fields": MODEL_FIELDS, "models": m1_models,
                 "raw_score_thresholds": m1_thresholds}, output / "m1_isolation_forest.joblib")
    joblib.dump(m2, output / "m2_random_forest.joblib")
    _plot(y_test, {"M1 Isolation Forest": m1_scores, "M2 Random Forest": m2_scores}, output / "roc_pr.png")
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in normal_paths + labelled_paths}
    result = {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
              "feature_spec_version": FEATURE_VERSION, "model_fields": list(MODEL_FIELDS),
              "fit_seeds": sorted({r['seed'] for r in fitting_rows if type(r.get('seed')) is int}),
              "calibration_seeds": sorted({labelled[i]['seed'] for i in validation_idx if type(labelled[i].get('seed')) is int}),
              "split": {"seed": seed, "test_size": test_size, "group_by": "run_id",
                        "train_windows": int(len(train_idx)), "test_windows": int(len(test_idx)),
                        "train_runs": sorted(set(np.array([r["run_id"] for r in labelled])[train_idx])),
                        "test_runs": sorted(set(np.array([r["run_id"] for r in labelled])[test_idx])),
                        "validation_runs": sorted({labelled[i]["run_id"] for i in validation_idx}),
                        "calibration": "validation runs" if split_manifest is not None else "training distribution; exploratory only"},
              "samples": {"normal_fit_windows_by_role": {role: len(rows) for role, rows in clean_by_role.items() if len(rows) >= 20}, "labelled": dict(Counter(map(str, y))),
                          "holdout": dict(Counter(map(str, y_test)))},
              "models": {"m1_isolation_forest": {"role_models": sorted(m1_models), "percentile_threshold": 1 - contamination, "raw_score_thresholds": m1_thresholds, "metrics": _metrics(y_test, m1_scores, m1_predicted)},
                         "m2_random_forest": {"threshold": m2_threshold, "metrics": _metrics(y_test, m2_scores, m2_scores >= m2_threshold)}},
              "input_sha256": hashes,
              "limits": "Offline evaluation only. Results apply only to these labelled lab runs and do not enable containment."}
    (output / "metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", type=Path, action="append", required=True, help="Clean collector JSONL; repeatable")
    parser.add_argument("--labelled", type=Path, action="append", required=True, help="Annotated JSONL; repeatable")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=.25)
    parser.add_argument("--split-manifest", type=Path, help="Disjoint train/validation/test run identifiers")
    parser.add_argument("--contamination", type=float, default=.05)
    args = parser.parse_args()
    output = args.output or ROOT / "artifacts" / "ml" / uuid.uuid4().hex
    try:
        result = train(args.normal, args.labelled, output, seed=args.seed, test_size=args.test_size,
                       contamination=args.contamination,
                       split_manifest=json.loads(args.split_manifest.read_text()) if args.split_manifest else None)
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"check": "ml_training_failed", "error": str(exc)[:512]}))
        return 1
    print(json.dumps({"check": "ml_training_complete", "output": str(output), "models": result["models"]}, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
