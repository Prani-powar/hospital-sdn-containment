# Standalone Isolation Forest: learned detection in the local lab

M1 now has a normal-only training workflow. Random Forest and attack-labelled
training examples are not required. The default remains M3 for reproducibility;
starting M1 requires an explicit trained model directory. The dashboard keeps
its existing design and displays M1's measured score and learned threshold.

## What changes

Each role receives an sklearn IsolationForest (200 trees, fixed random seed,
one CPU worker) fitted to ten behavioural counters. A StandardScaler precedes
it. A separate normal calibration run sets the 99th-percentile raw anomaly
threshold. Fit and calibration run IDs AND experiment seeds must be disjoint.
All six roles need at least 20 valid fit and 20 valid calibration windows.
This is a minimum input gate, not sufficient statistical validation.

A score strictly ABOVE the calibrated threshold is anomalous. Ties are not all
flagged when a normal workload is constant. Constant input fields are recorded;
a model trained on an overly narrow workload may miss attacks or flag legitimate
changes. Broader normal workloads, independent attacks, and held-out tests are
still necessary. We do not ship an artificial fixture model as a hospital model.

The live policy uses this learned alarm instead of M3's destination/port cutoff.
Role policy, valid-window checks, consecutive-sample hysteresis and authenticated
switch readback remain in place. ML decides suspicion; deterministic policy
still controls which response is safe. No model error silently falls back to M3.

## Linux Mint setup

Stop other lab launchers using Ctrl+C first. Do not clear unrelated bridges or
kill other processes. Preserve existing finite reports and trained artifacts.
Use a dedicated Python environment that can see the system Mininet package:

```bash
/usr/bin/python3 -m venv --system-site-packages .venv-ml
.venv-ml/bin/python -m pip install -r infra/requirements/isolation.txt
```

If venv is unavailable, install the matching Mint/Ubuntu python3-venv package.
Docker, OVS, Mininet and the existing hospital-controller:lab image must already
work. No model is trained inside the controller container.

## One command to collect and train

```bash
sudo .venv-ml/bin/python scripts/bootstrap_isolation.py --output artifacts/isolation-normal
```

This takes three finite owned B0 normal-only runs (seeds 101,102,103), each with
60 seconds of measurement plus warm-up/startup. Clinical services and per-role
normal agents run; seed activation and synthetic attack propagation are disabled.
Each run is cleaned up normally before the next. A failure stops the workflow;
raw logs remain and there is no automatic destructive cleanup or blind retry.

Seeds 101 and 102 fit the models; seed 103 calibrates them. The command verifies
COMPLETE instrumentation, empty attack ground truth, and valid normal windows.
Output:

- normal-101/102/103.jsonl: measured, normal-labelled feature windows.
- collection-101/102/103.log: collection logs pointing to raw experiment runs.
- model/m1_isolation_forest.joblib: six fitted models and raw thresholds.
- model/metrics.json: provenance, input hashes, role counts, calibration alarm
  fractions, constant fields and limitations. No attack accuracy is invented.

The output directory must be new. If a run fails, inspect its exact error before
attempting another collection. Windows cannot run the native Mininet collector;
use Linux Mint or a properly configured Linux VM. Do not train from the hosted
website's simulated animation or from unverified traffic labelled clean.

## Start the learned detector

```bash
sudo .venv-ml/bin/python scripts/lab.py --detector M1 --model-directory artifacts/isolation-normal/model
```

Open http://127.0.0.1:8088, choose Read local controller, then select a source
in REAL LOCAL LAB SESSION and start its harmless probe. M1 should be shown as
the detector. Whether a given probe is detected must be observed, not assumed.
Switch readback is still required for confirmation and spatial containment.
A released rule does not establish that a device is clean.

For a finite research test on an untouched seed:

```bash
sudo .venv-ml/bin/python -m experiments.run --baseline B3 --scenario S1 \
  --partition test --seed 201 --detector M1 --model-directory artifacts/isolation-normal/model
```

Repeat on independent scenarios/seeds, retain misses and measure false alarms,
latency and clinical preservation. Never tune repeatedly against test seeds.

## Train from already collected normal data

Use experiments.dataset to export labelled controlled runs, then:

```bash
.venv-ml/bin/python -m decision.train_isolation \
  --train normal-101.jsonl --train normal-102.jsonl \
  --calibration normal-103.jsonl --output artifacts/my-isolation-model
```

Inputs must be explicitly normal-labelled validation-seed data, with valid
features and no duplicate windows. Attack labels, test seeds, overlapping
fit/calibration seeds and missing roles are rejected. Joblib models are trusted
local executable artifacts; never accept arbitrary downloaded model files.
The existing dual-model training path remains supported, and M2 selection with
an M1-only artifact fails clearly before the live pipeline starts.

## Verification boundary

Portable tests fit actual sklearn models on test fixtures, load M1 without an
M2 file, exercise its score through the live policy/outbox, check tie handling,
and reject leakage/invalid inputs. They do NOT establish real-world detection
accuracy, actual Mininet data quality or OVS enforcement success. Those require
the Linux collection and independent live tests described above.
