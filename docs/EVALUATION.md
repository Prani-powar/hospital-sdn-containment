# Measured results and evidence reassessment

The results exporter reads a finite demo report, reassesses its outcome and writes:

- summary.md: a mentor-readable phase/service table and available action timing.
- clinical.csv: per-phase C1–C5 attempt/reply counts and weighted mean RTT.
- summary.json: machine-readable assessment, notes and SHA-256 of the source report.

The finite demo runner invokes it automatically after retaining its original JSON
report. An optional export failure is reported explicitly; the original measurement
file remains available. Files are written into a new summary directory, never over
an earlier dataset. No measured success report is bundled with the repository.

For later use with existing run files, from the repository root:

```bash
python3 scripts/summarize_demo.py \
  --input artifacts/demo/RUN_ID/report.json \
  --output-directory artifacts/demo/RUN_ID/export-review \
  --events artifacts/demo/RUN_ID/events.jsonl artifacts/demo/RUN_ID/decisions.jsonl
```

This operation works on Windows too. Audit files are optional; omit --events when
only the report is available. Missing timing evidence stays unmeasured. Input files
must come from the same run; malformed or mixed-run audit records are rejected.

## What is rechecked

A saved PASS label is insufficient. The exporter checks required phases, configured
clinical source sets, nonzero replies, loss, minimum recorded probe coverage,
matching experiment/variant/measurement intervals, actual offered-load arithmetic,
ping outcomes and ordered action confirmations. Execution or cleanup errors cannot
be hidden by surviving successful probe records. A recorded FAIL is never upgraded.
The CSV counts cover measured phase windows, not every probe in the 90-second run.
Mean RTT is weighted by received replies. Missing RTT is not converted to zero.

The source hash allows reviewers to identify exactly which report was summarized.
This is a consistency assessment of supplied files, not independent verification
that the experiment occurred. The exporter cannot certify an externally forged
report or reconstruct packets not captured by the lab.

## Timing scope

Rule-request-to-readback timing requires matching run, host and proposal ID plus a
readback_confirmed rule_installed event (or a released event for release timing). Probe-launch-to-readback measures from the
observed launch of the harmless test process. It is not first-packet-to-containment
latency. Missing requests, wrong-host events and unconfirmed writes remain unmeasured.
No last-malicious-packet, infection-spread or trained-ML accuracy metric is invented.

## Validation

141 Python tests pass locally: 40 controller, 42 decision, 34 topology, five
bridge, ten runner/reporting, and six infrastructure tests, plus four new
serve-bridge POST-proxy tests. Node UI logic checks also pass. New combined
recovery tests exercise mid-drop disconnect, clinical-floor recovery, explicit
scoped release and concurrent host-policy preservation using stateful fake
switches. They do not replace actual Ryu/OVS restart experiments.
Six exporter tests cover counts/RTT, evidence inconsistencies, timing correlation,
audit identity, exclusive writes/provenance and corrupt input.

## Remaining project work

| Workstream | Current position | Required next evidence |
|---|---|---|
| Integrated automatic demo | Implemented and locally tested | New image build and actual Mint/Mininet/OVS run |
| Role and failure coverage | Pure compiler/coordinator tests | Actual ISOLATE/RESTRICT/PROTECT, expiry and restart experiments |
| Evaluation | Exporter ready | Repeated real runs; measured latency, loss and workload settings |
| Learned detector | M1 per-role Isolation Forest / M2 Random Forest training, scoring and leakage-safe evaluation tooling implemented; threshold policy remains live baseline | Controlled labelled runs, trained artefacts and reported validation results |
| Mentor presentation | Interactive console and report format ready | Use actual results and explain remaining limits clearly |

## Design analysis and self-review

1. Requirement: reproducible mentor-readable results from actual saved run files.
2. Assumptions: shared monotonic clock on one lab machine and uniquely identified runs.
3. Risks: trusting saved labels, mixed runs, missing observations and misnamed latency.
4. Options: copy status labels or reassess counters/identities; choose reassessment.
5. Decision: bounded JSON/audit reads, exact correlations, source hash and exclusive outputs.
6. Tests: synthetic fixtures exercise valid and inconsistent evidence; no real lab
   outcome is asserted by those fixtures. Real measurements remain pending.

The exporter does not change network policy, train a model or create missing data.

## Multi-seed baseline aggregation

After each real experiment, create one JSONL record containing its reassessed
`evidence_status`, baseline (`B0`–`B3`), scenario (`S1`–`S3`), seed, safety
outcome and only the metrics actually measured. Then aggregate it with:

```bash
python -m scripts.aggregate_benchmarks --input artifacts/benchmarks/runs.jsonl \
  --output artifacts/benchmarks/summary --minimum-runs 10
```

The exporter writes JSON and CSV group summaries with a Student-t 95% interval
across seeds. It rejects failed evidence, critical-device false-isolation cases,
duplicate baseline/scenario/seed identities and non-finite values. An incomplete
matrix exits nonzero and remains visibly incomplete rather than being presented
as an experiment result.

The step-by-step Linux measurement procedure and benchmark-record schema are in
[the lab evaluation runbook](LAB_EVALUATION_RUNBOOK.md).
Recovery tests use simulated switch tables and must be repeated on actual OVS.
