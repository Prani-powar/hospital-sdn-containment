# Lab evaluation runbook

This runbook is for the Linux Mint/Ubuntu operator. It does not replace a real
OVS measurement with a dashboard animation or a unit test.

## Preconditions

1. Use the current repository revision on a Linux machine with Docker, Mininet,
   Open vSwitch and Python 3 available. Do not use this workflow on a production
   network.
2. Run the portable tests and retain their terminal output:

   ```bash
   python3 scripts/check.py
   ```

3. Build the controller image from the checked-out source:

   ```bash
   sudo docker build -t hospital-controller:lab -f controller/Dockerfile .
   ```

4. Validate the finite plan before using root:

   ```bash
   python3 scripts/demo.py --validate-only --enforce
   ```

## Controlled B3 runs

Run an office/guest ISOLATE case and a clinical/IoMT/vendor RESTRICT case. Each
execution creates a unique `artifacts/demo/RUN_ID` directory; preserve the full
directory, especially `report.json`, `events.jsonl`, `decisions.jsonl`, worker
logs and generated summary.

```bash
sudo /usr/bin/python3 scripts/demo.py --enforce --host=reception1
sudo /usr/bin/python3 scripts/demo.py --enforce --host=monitor2
sudo /usr/bin/python3 scripts/demo.py --enforce --host=vendor_gw
```

For every run, record the run ID, source, action, offered rate/duration, image
tag and commit. A PASS is valid only when the exported reassessment is also PASS.

## Dataset and ML workflow

Collect clean role traffic and attack traffic separately. Each seed must have a
distinct collector run ID. Do not merge a clean run with a run that has unknown
post-attack hosts.

```bash
# On a known-clean controlled run
python3 -m decision.label_windows --features CLEAN_FEATURES.jsonl --normal-only \
  --output artifacts/ml/clean_seed_01.jsonl

# On an attack run with its actual event evidence
python3 -m decision.label_windows --features ATTACK_FEATURES.jsonl \
  --events artifacts/demo/RUN_ID/events.jsonl --output artifacts/ml/attack_seed_01.jsonl

# Only after sufficient clean data exists for every role
python3 -m decision.ml_pipeline --normal artifacts/ml/clean_seed_01.jsonl \
  --labelled artifacts/ml/attack_seed_01.jsonl --output artifacts/ml/experiment_01
```

M1 requires at least 20 normal training windows for each role represented in the
labelled evaluation data. Training output is not authority to change enforcement:
review its metrics and calibration before displaying scores with `decision.live`.

## B0–B3 experiment record contract

The current real runner exercises B3. B0/B1/B2 require separately reviewed
scenario/policy variants before a comparison claim can be made:

- B0: no adaptive response.
- B1: static, pre-installed segmentation with no dynamic response.
- B2: role-blind isolation, in an explicitly approved safety-separated lab
  variant only; never run it against clinical service traffic by accident.
- B3: the current role-aware policy with protected C1–C5 allows.

After each reassessed real run, append one JSON object to
`artifacts/benchmarks/runs.jsonl`. Include only measured values; omit a metric if
it is unavailable. `false_isolation_critical` must be independently reviewed,
not inferred from missing data.

```json
{"schema_version":1,"baseline":"B3","scenario":"S1","seed":1,"run_id":"RUN_ID","evidence_status":"PASS","false_isolation_critical":false,"metrics":{"time_to_contain_s":1.23,"critical_flow_success_rate":1.0,"rule_count":12}}
```

Aggregate only after collecting all baseline/scenario/seed combinations:

```bash
python3 -m scripts.aggregate_benchmarks --input artifacts/benchmarks/runs.jsonl \
  --output artifacts/benchmarks/summary --minimum-runs 10
```

The command exits nonzero until all 4 × 3 groups have ten valid runs. That is a
coverage signal, not a failed network experiment.

## Required remaining external evidence

- S1 reception scan/spread, S2 slow scan at multiple rates and S3 vendor-server
  probing, each with harmless synthetic traffic only.
- B0–B3 comparison across at least ten seeds per scenario.
- Critical flow success and RTT during every attack phase.
- Detection/enforcement/containment timing, infection/spread markers, false
  positives, false isolation, controller CPU/memory and rule count.
- 12/24/48-host scalability, threshold/window sweep and hysteresis/role-profile
  ablations.
- Controller/switch restart and expiry recovery experiments.

Do not fill blank results with simulated values. Preserve failed runs and explain
them in the report.
