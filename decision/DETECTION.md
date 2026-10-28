# Fan-out detector and role-aware policy planner

This is actual detection/policy code, not the dashboard animation. It can process
recorded feature JSONL from `collect_features.py`. It emits Score records and
versioned Action proposals. **It sends zero controller commands.** Desired policy
is kept separate from observed rule state; `applied` is always false in this module.

## Design Analysis

1. Requirement: detect off-profile fan-out and choose role-appropriate responses,
   with consecutive-window confirmation, clean-window recovery and finite leases.
2. Assumptions: trusted local feature collector, one synchronous owner of planner
   state, the source-ingress-proxy-v1 specification and hospital-peer-profile-v1.
   Thresholds are provisional lab settings, not clinically validated or trained ML.
3. Risks: normal administration can resemble scanning; missing data can look clean;
   duplicate/overlapping windows can inflate evidence; a critical server's anomaly
   does not establish which inbound source to block; desired plans can be mistaken
   for installed rules.
4. Options: immediate action versus hysteresis; packet volume alone versus fan-out
   with off-profile activity; guessed server-source attribution versus review.
5. Decision: two consecutive anomalous windows, three clean windows, configurable
   role thresholds and 20-second desired leases. Reject spoofed, stale and invalid
   evidence; do not guess PROTECT sources. Every proposal states applied:false.
6. Validation: 15 new tests, 33 total decision tests. They exercise all medical,
   clinical and critical-server hosts, full feature-to-policy arithmetic, duplicates,
   resets, source attribution, lease expiry, vendor escalation and offline replay.
   Controller enforcement, live detection accuracy and action timing remain unverified.

## Detection semantics

`configs/detection.yaml` defines one threshold pair per role. A window is anomalous
when at least one threshold is reached (`unique_dst` OR `unique_dst_ports`) AND
`off_allow_list_flows` reaches its configured minimum. Packet volume by itself does
not trigger this detector. `anomaly_score` is the maximum threshold ratio, gated by
the off-profile minimum; it is not a probability or ML confidence.

This is the M3-style threshold baseline used by the live policy path, not the
offline M1/M2 models. `ml_pipeline.py` now provides Isolation Forest and Random
Forest training with run-grouped holdout evaluation; it is deliberately not wired
to live containment. See `../docs/ML_PIPELINE.md`. There is still no measured
false-positive rate or recall until controlled labelled runs are collected.

Feature windows overlap. Two consecutive windows are two unique cuts, not independent
statistical observations. Older/duplicate timestamps do not advance streaks. Invalid
quality, spec/profile mismatch, long gaps or epoch changes break evidence streaks.
Invalid data never counts towards clean release. All shared Feature, Score, Action
and Event field names are unchanged; proposal IDs, versions and replay context are
outside the Action contract.

## Role and safety handling

- Admin and guest: propose ISOLATE, preserving configured lab management peers.
- Clinical workstations and IoMT: propose RESTRICT with configured vital peers;
  sustained anomalies never escalate these roles to ISOLATE.
- Vendor: propose RESTRICT, then ISOLATE only after three additional anomalous cuts
  in desired restricted state. A real executor must confirm the earlier restriction
  before treating those cuts as evidence of persistence under enforcement.
- Critical server: raise a review status without a distinct attributed malicious
  source. An attributed PROTECT proposal is rejected when the pair is in the
  protected clinical-pair list. Never isolate the server itself.

The configured `dns_ad` management peer is an explicit lab proposal, not proof that
an SSH/management service exists there. This module specifies peers, not compiled
port-specific switch rules. Network enforcement needs a separately reviewed rule
compiler with actual management ports and immutable C1-C5 rules. Do not execute
these peer lists blindly as broad production ACLs.

Protected pairs come from configuration; the future compiler must also check actual
critical rules and fail on incomplete policy. Configuration validation refuses to
remove a listed vital peer from an IoMT/clinical allowed-peer list. Human override,
B3a/B3b/B3c policy variants and authentication are not implemented here.

## Desired state, time and concurrency

Only a fixed 24-host state map is retained; streaks are capped and proposals are
returned to the caller rather than stored in an unbounded queue. All state mutation
is synchronous and contains no network or cooperative yield. One actor/coroutine
must own the instance; it is not a shared multi-thread service.

NORMAL -> SUSPECT -> CONTAINED -> RELEASING -> NORMAL describes **desired state**.
CONTAINED does not mean OVS has installed a rule. Every proposal includes a stable
ID, per-host monotonic version, controller epoch and planner-process epoch, suitable for later executor
idempotency. A planner restart gets a new namespace; versions are not durable across restarts. This does not implement executor duplicate/stale rejection itself.

`tick(now_ns)` must be scheduled independently by a future live service. It expires
desired leases even if telemetry stops, and returns RELEASE proposals without
claiming rule deletion. An already proposed restriction is not renewed by duplicate
windows or a controller restart. An epoch change resets evidence but retains desired
leases for subsequent reconciliation; actual rules must be queried separately.

The replay runner calls tick using evidence time. It emits actual process-monotonic
`scored` and `decision` Events with explicit offline_replay metadata. It never emits
`rule_requested`, `rule_installed`, `released` or fabricated enforcement timestamps.
A RELEASE proposal alone is not evidence of release.

No FastAPI server, SQLite writer, live scheduler, controller-action client or mutation
endpoint is introduced in this increment. Per-host execution serialization,
reconciliation, acknowledged-rule TTLs and durable single-writer state remain the
controller/decision integration work. No blocking HTTP is added to either runtime.

## Storm and polling limits

The existing source/global packet-in guards can hide scan evidence. The extractor
invalidates windows on guard drops or sequence gaps; this detector will not relabel
those intervals benign. Sustained pressure can prevent detection entirely through
this path. A separate pressure/fast-path mechanism and its named evaluation variant
are still needed. Do not claim S1 high-rate resilience from these tests.

Normal first-decision budget includes the initial five-second feature warm-up when
needed, poll alignment and delivery, N-1 subsequent feature steps, feature computation
and scoring/policy work. This module can time scoring/decisions in replay but has no
REST enforcement or switch-install measurement. End-to-end containment latency is
unbounded until enforcement exists, and gaps can prolong detection without bound.
No controller rule shifts, full-packet settings, meters or clinical-floor variants
are changed here.

## How to verify (no live lab needed)

```bash
python3 -m unittest discover -s decision/tests -v
python3 -m decision.replay_detection --demo --summary-only
```

Expected: 33 tests pass. The second command is explicitly synthetic input processed
by the real detector/planner. It proposes 3 ISOLATE actions (two office/guest actions
and one vendor escalation), 3 RESTRICT actions and 5 RELEASE actions. It prints
`network_actions_sent: 0`. Critical-server fixtures require source attribution and
therefore produce no guessed PROTECT action.

To process a real collector output later, use its actual path:

```bash
python3 -m decision.replay_detection --input artifacts/features/ACTUAL_RUN_ID.jsonl
```

Replace ACTUAL_RUN_ID with a saved run ID. The runner reads poll_received Events to
track controller epochs. Inputs without valid epoch metadata fail closed. Input is
limited to 200 MB, 100,000 records and one MB per record. This is replay of measured
features, not live enforcement. Full events are printed unless --summary-only is set.
Tests use unittest and are also compatible with pytest in the pinned services image.
No new package dependency is needed.

## Self-review

No switch rules are installed/deleted, no clinical allow is overridden, and no
protected role can get an automatic ISOLATE proposal. Counter/spec quality is checked,
roles are validated against inventory, and duplicate evidence cannot renew leases.
Tests exercise real feature extraction into actual decision code, not a timer-driven
UI simulation. Synthetic replay outcomes are labelled, and no live accuracy,
containment success or production readiness is claimed. The next integration needs
an acknowledged controller-action boundary; these proposals are not that boundary.
