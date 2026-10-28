# Offline ML pipeline (Member C)

`decision.ml_pipeline` trains and evaluates two offline research models from
saved feature windows. It is not imported by the live detector and has no
controller/action-client dependency.

- **M1:** a separate Isolation Forest per device role, trained on valid normal
  windows only (plus the normal partition of labelled training runs). Each
  labelled role needs at least 20 normal training windows.
- **M2:** supervised Random Forest, trained on labelled normal/attack runs.
- The holdout split is grouped by `run_id`, so overlapping windows from one run
  cannot appear in both train and test data.

## Labelled data contract

Start with `feature_window` records produced by `decision.collect_features` and
add a top-level `label` (`normal`/`attack` or `0`/`1`) plus a `run_id`. Keep the
original `feature` and valid `quality` objects unchanged. A compact row is:

```json
{"run_id":"s1_seed_07","label":"attack","feature":{...},"quality":{"valid":true,"feature_spec_version":"source-ingress-proxy-v1"}}
```

The `--normal` files may be ordinary collector output and are treated as normal.
The labelled set needs at least two distinct normal runs and two distinct attack
runs; use several seeds rather than relabelling overlapping windows as separate
runs.

### Creating labels from project evidence

Use the helper below after a controlled clean run or a run with a recorded
`attack_start` event. It never calls a post-attack window from another host
normal: its infection state is unknown unless the scenario runner records it.

```bash
# Controlled normal run
python -m decision.label_windows --features artifacts/features/clean.jsonl \
  --normal-only --output artifacts/ml/clean-labelled.jsonl

# Controlled attack run; event logs contain the source and monotonic start time
python -m decision.label_windows --features artifacts/features/run.jsonl \
  --events artifacts/demo/RUN_ID/events.jsonl \
  --output artifacts/ml/attack-labelled.jsonl
```

The resulting JSONL is accepted by `--labelled`. Keep a distinct `run_id` for
every seed. For spread metrics, extend the scenario generator to emit an
infection event for each affected host; do not infer infection from traffic.

## Train

```bash
python -m decision.ml_pipeline \
  --normal artifacts/features/clean_seed_01.jsonl \
  --normal artifacts/features/clean_seed_02.jsonl \
  --labelled artifacts/features/labelled_s1.jsonl \
  --labelled artifacts/features/labelled_s2.jsonl \
  --output artifacts/ml/experiment_01
```

The output directory is created only once and contains M1/M2 joblib files. The
M1 artifact contains one named model and threshold per role; scores are
calibrated against that role's clean training-score distribution before combined
holdout curves are calculated. It also contains
`metrics.json`, and `roc_pr.png`. Metrics include ROC-AUC, average precision,
precision, recall and F1 on the held-out runs. They are empirical only for the
recorded lab dataset; do not report metrics until controlled normal and attack
runs have been collected and reviewed.

## Dependencies and safety

The service requirements include scikit-learn, NumPy, Matplotlib and joblib.
Training rejects invalid/mismatched feature windows, missing labels, and splits
that would leak a `run_id` across training and test. It sends no traffic,
modifies no rules, and does not replace the threshold policy automatically.

## Read-only live score display

After training and review, a locally generated artifact directory can be added
to the finite decision runner:

```bash
python -m decision.live --ml-model-directory artifacts/ml/experiment_01
```

M1/M2 values then appear as `ml_scores` in the live status snapshot. They are
observational only: the existing reviewed threshold policy still controls all
proposals. Never point this option at an uploaded or untrusted joblib file;
joblib uses Python deserialization and is not a safe interchange format.
