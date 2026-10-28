# Research implementation and execution gates

This supplements the finite demo and persistent mentor lab; neither startup
path is replaced. The dashboard design is unchanged. No new result values are
claimed here. Portable tests and a real UDP loopback check do not validate OVS.

## What the audit found

| Requirement | Existing before this change | Added here | Real Linux evidence |
|---|---|---|---|
| M1/M2 action binding | Observational ML scores only | Explicit M3/M1/M2 selection, same validated role-aware actor | Pending |
| S1–S3 | One non-spreading fan-out probe | Finite seeded marker listeners/propagation, per-host truth logs | Pending |
| Normal traffic | C1–C5 clinical workers | Seeded per-role request/reply workload in every host | Pending |
| Clinical preservation | Continuous five-group probes existed | Every research run retains raw probes and sampled summaries | Pending |
| B0/B1/B2/B3 | B0 observe and B3 finite path | Separate experiment modes; B2 intentionally lacks clinical protection | Pending |
| Timing | Monotonic event contracts existed | Defined latency boundaries, warm-up, CPU affinity, boot/config/source provenance | Pending |
| Train/validation/test | Run-group holdout existed | Explicit disjoint manifest, validation calibration, held-out fit rejection | Pending |
| Scale / sensitivity | No execution harness | 12/24/48 configs, S2 rate, window, threshold, hysteresis/profile sweeps | Pending |
| Failures | Fake-switch disconnect/idempotency tests existed | TTL/RELEASE race and owned process/controller/switch fault injection | Pending |

## Setup and one small smoke run

Use a disposable Linux Mint/Ubuntu VM or the isolated local lab. No real patient
network or clinical device is part of this testbed. Close the persistent lab
with Ctrl+C before experiments: ports, bridge names and artifact owners must
not overlap. Never use broad OVS deletion or kill unrelated services.

Install system Mininet, OVS, Docker and Python using `infra/setup.sh` after
reviewing its instructions. The existing `infra/Dockerfile.ryu` pins Ryu's
Python stack; `infra/requirements/services.txt` pins Python service/ML packages.
The host kernel, apt package revisions and OVS are NOT bit-for-bit pinned;
each run records installed versions and the Docker image ID. Archive those
versions or a VM snapshot for an exact replication.

From the repository root:

```bash
sudo systemctl start docker openvswitch-switch
sudo docker build -t hospital-controller:lab -f controller/Dockerfile .
/usr/bin/python3 scripts/check.py
/usr/bin/python3 -m experiments.run --validate-only --baseline B3 --scenario S1 --seed 101
sudo /usr/bin/python3 -m experiments.run --baseline B3 --scenario S1 --seed 101
```

The experiment starts its own controller, topology, normal agents, clinical
workers and decision process, then exits and cleans up. It does not start a
web dashboard or overwrite the finite demo's `report.json`. Its separate output
is `artifacts/demo/<run_id>/research-report.json`. Failed/incomplete runs remain
there with errors; do not edit them into successes.

For M1 or M2 add `--detector M1 --model-directory /absolute/trusted/models`.
`decision.live --detector M1|M2 --enforce` also uses that selected model with the
normal authenticated readback actor. M3 is the default. No missing-model
fallback exists. A model error breaks evidence streaks; stale data cannot
produce a new action. Desired leases can still expire and request reconciliation.

## Baselines and scenarios

- **B0:** static-fabric forwarding, observational detector; no containment.
  This is not a MAC-learning-switch benchmark: the controller already uses a
  configured hospital fabric. State this distinction in the paper.
- **B1:** static cross-segment IPv4 drops at priority 59000, explicit synthetic
  normal request/reply and clinical service exceptions at 60000. Same-segment
  communication remains allowed. No detection-driven changes. This is a
  specified coarse segmentation baseline, not an optimally tuned enterprise ACL.
- **B2:** the same selected detector/hysteresis, then source and destination
  IPv4 drops at 62000 on all six switches, with **no clinical exemption**.
  The separate benchmark executor confirms exact cookie/match/TTL/action
  readback. It never relaxes the normal controller's protected-role checks.
  Clinical failure is an outcome to retain, not an instrumentation failure.
- **B3:** existing role-aware policy, authenticated proposals, clinical allows
  and controller readback. Critical servers still require attributed-source
  protection or human review; a marker infection does not bypass this invariant.

S1 starts at reception1 at 4 packets/s. S2 starts at reception1 and sweeps
**0.5, 1, 2, 4 packets/s per infected agent**. S3 starts at vendor_gw and
prioritizes PACS/imaging/EHR contacts. Every host's normal requests continue.
Each agent records an in-memory synthetic infection when a valid run marker
arrives and then sends bounded markers itself. No exploit, malware, host process
creation, remote shell or persistent infection is used. Seed-source activation
is labelled separately from a marker received through the emulated network.
These are explicit operational S1–S3 definitions, not claims that earlier
unspecified scenarios or real malware behaviours were reproduced exactly.

The 12-host variant keeps one source in each of C1–C5. The 24-host variant
keeps all original sources. The 48-host variant adds 24 normal/attack-capable
endpoints but keeps the original clinical sources. Thus report clinical-source
counts alongside host counts: this is endpoint/workload scaling, **not** a
constant proportion of clinical devices or switches. The research floor has a
separate named variant for the reduced source inventory; the original default
C1–C5 floor contract remains exact.

## Measurement definitions

All event times use Linux CLOCK_MONOTONIC in nanoseconds, shared by host network
namespaces and ordinary Docker containers on the same boot. Never combine
clock values from another machine, VM boot or imported old run.

- Attack onset: first recorded actual `attack_send` socket send by the seed
  source. The timestamp is immediately after successful sendto, not process launch.
- Detection: first `detector_triggered` event after required consecutive windows.
- Enforcement: switch rule-table readback confirmation (`rule_installed` or the
  benchmark-only `experiment_isolation_confirmed`). HTTP acceptance is not this.
- Detection delay = detection minus onset; enforcement delay = readback minus
  detection; total containment latency = readback minus onset.
- Missing detection/confirmation is **null**, with containment_observed=false.
  Means condition on observed events; show misses beside them. Baselines that
  never dynamically contain must not receive a fictitious zero latency.
- Infection/spread is marker receipt, never inference from attempted sends.
  False isolation means confirmed isolation/restriction of a host not yet
  infected in this controlled marker model. Detection precision/recall/F1 are
  host-level alarms; model holdout metrics are feature-window metrics. Do not
  merge those units. Uninfected but noisy hosts are false positives by design.
- Clinical delivery and RTT come only from recorded synthetic request/replies.
  Counts in the report cover the measurement interval; early warm-up is excluded.
  The initial 12 seconds (at least window+3) warm forwarding, probes and detector.

Two distinct allowed CPUs are selected by default: one for the Docker controller
and one shared by launcher/decision/agents. Override with `--controller-cpu N
--workload-cpu M`. Affinity is inherited by owned children and restored afterward.
Existing OVS daemon affinity is deliberately unchanged. Shared kernel paths,
CPU frequency, SMT siblings, other processes and polling still introduce noise.
Pinning is not a claim of real-time determinism. Report core topology and load,
prefer idle physical cores and a fixed VM resource allocation. Samples report
one-core controller CPU delta, maximum RSS, and reported access-switch rule rows;
the last is not an all-table/all-switch rule census.

## Validation, model training and held-out execution

Use seeds 101–110 for configuration development and 201–210 for final reporting.
Do not tune on the latter. Generate labels from COMPLETE controlled runs:

```bash
python3 -m experiments.dataset --run artifacts/demo/RUN_ID --output labels-RUN_ID.jsonl
```

Boundary-overlapping infection windows and windows suppressed by confirmed
containment are omitted. Pure marker labels describe this testbed only.
Prefer B0 collection for model training so response censorship does not dominate
training data. Archive all raw truth/feature files and hashes before training.

Create a split manifest with disjoint run IDs:

```json
{"train_runs":["TRAIN_RUN_IDS"],"validation_runs":["VALIDATION_RUN_IDS"],"test_runs":["HELD_OUT_RUN_IDS"]}
```

Each split needs both labels and validation needs clean windows for every
modelled role. `--normal` must include only training-run clean windows, never
validation/test windows. At least 20 clean fit windows per role are required.
M1 calibration uses validation normals; M2 selects among .25/.5/.75 by validation
F1, then evaluates the untouched test partition once. Without an explicit
manifest the old exploratory group holdout remains available, but it is not
eligible for held-out closed-loop claims.

```bash
python3 -m decision.ml_pipeline --normal clean-train.jsonl \
  --labelled labelled-runs.jsonl --split-manifest split.json --output artifacts/models/FROZEN
```

Held-out ML execution requires recorded fit/calibration seeds in 101–110 and a
validation split. Do not repeatedly inspect test performance while tuning.
Freeze all selected configs and model hashes; the matrix stores the selected
config manifest hash. A human is still responsible for avoiding selection bias.

## Matrices, scaling, sweeps and ablations

Plan first (no root, network or Docker started):

```bash
python3 -m experiments.matrix --partition validation --plan validation-plan.json
```

This produces **240 runs**: B0–B3 × ten seeds × (S1 + four S2 rates + S3).
At roughly a minute per run, this is several hours, before ML/scaling/sweeps.
Do not launch a full matrix until a single small run has complete instrumentation.

Add `--detectors M3 M1 M2 --model-directory ...` for the selected-model comparison.
Add `--scalability` for 12/24/48; `--sweeps` for windows 2/5/10, threshold scale
.5/1/2, hysteresis 1/2 and the unprofiled-feature ablation. B2 vs B3 separately
ablates role-aware enforcement. These switches can produce thousands of runs;
read the generated count and plan before adding `--execute` under sudo.
Threshold scaling affects M3, not trained M1/M2 parameters.

Freeze a JSON with `window`, `threshold_scale`, `hysteresis` selected on validation.
Then run the untouched test partition:

```bash
sudo /usr/bin/python3 -m experiments.matrix --partition test \
  --frozen-plan selected.json --plan test-plan.json --execute
python3 -m experiments.aggregate --output research-summary.json
```

Runs execute sequentially and stop on incomplete instrumentation. No automatic
cleanup of stale lab resources or silent retry occurs. New aggregation groups
by all experimental factors; it retains misses and clinical failures. Legacy
`scripts.aggregate_benchmarks` is not suitable for this new research schema.

## Failure checks

Portable tests cover duplicate/stale proposals, disconnects, readback failure,
controller epoch changes, unknown previous leases, uncertain writes, censored
features, selected-model failure, TTL expiry racing RELEASE and scoped deletion.
They use fake switches and do not replace physical OVS evidence.

For owned real faults add one of:

```bash
sudo /usr/bin/python3 -m experiments.run --fault decision-stop
sudo /usr/bin/python3 -m experiments.run --fault controller-restart
sudo /usr/bin/python3 -m experiments.run --fault switch-disconnect
```

The expected fail-closed shutdown still returns nonzero. Inspect `fault.json`:
`halt_observed` is true only if the observed error matches the injected fault.
Controller restart occurs during an active scenario, so existing-rule behaviour
is exercised but recovery is not claimed: the planner refuses automatic takeover.
Automatic safe resumption after planner/controller restart, real TTL races,
duplicate HTTP submissions, sustained load and multiple VM/kernel versions
remain target-machine verification tasks. Preserve all fault logs.

## Evidence files and remaining gates

Each research run contains source/config hashes, image/package versions, affinity,
boot ID, configs, agent logs, decisions/features, ground truth, baseline rules,
clinical raw logs in the linked critical-suite run directory, sampled telemetry
and a report. Archive both run directories together. Never publish an action
token; workers receive no controller secret and no model files are accepted by
HTTP endpoints. Joblib artifacts are trusted local code; do not load arbitrary
model downloads.

Before any paper claims: run all checks in the target VM, all ten-seed measured
cells, independent model evaluation and fault/load runs; retain raw files.
**None of those real OVS runs was executed in this development environment.**

Persistent interactive ML mode (after producing trusted calibrated models):

```bash
sudo /usr/bin/python3 scripts/lab.py --detector M1 --model-directory /absolute/models
```

The dashboard labels the selected model threshold. The existing default M3
command and finite demo remain available. See THREAT_MODEL_AND_DATASET.md for
scope, literature rationale and dataset release requirements.
