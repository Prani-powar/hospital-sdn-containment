# Source-ingress feature extraction

This increment produces measurements and quality records. It does not score hosts,
install rules, implement containment, or provide a FastAPI service. Run it in a
separate Python process from Ryu. No controller image rebuild is needed for these files.

## Design Analysis

1. **Requirement restated:** produce the agreed per-host Feature contract from the
   read-only controller API, while recording when a valid measurement cannot be made.
2. **Assumptions:** the static hospital and the updated controller API are in use,
   and both processes share one machine's monotonic clock. Forward priorities have
   the meanings in the project's priority matrix. Profiles below are experimental
   peer expectations, not enforcement policies or validated clinical requirements.
3. **Failure modes and risks:** stale/partial polls; duplicate transit copies;
   expired or reset counters; missing packet-in history; controller restarts;
   wildcard clinical rules; source counters mistaken for delivered traffic;
   incomplete data silently becoming normal training examples.
4. **Options considered:** rates from every switch double-count paths; adding
   packet-ins to flow counters risks counting the same packet twice. Polls alone
   miss PacketOut-only tuples. Choose source-only counter deltas, separate tuple
   evidence from observations, and explicit invalidation rather than imputation.
5. **Decision and justification:** bounded sliding measurement windows, source
   attachment validation, counter-instance baselines, observation cursors, and
   experimental peer profiles. Invalid windows are discarded and re-warmed. A
   separate collector coroutine owns all state and reads through TelemetryClient.
6. **How we test and measure:** 18 deterministic/local-HTTP tests cover arithmetic,
   deduplication, wildcard groups, resets, clock bounds, gaps and state limits.
   Record real `poll_received` and `features_ready` events. Live C1 extraction on
   Mint and target Python 3.11 runtime verification remain required gates.

## Files and dependencies

- `features.py`: configuration validation, counter baselines and sliding windows.
- `collect_features.py`: finite async collector, Event records, JSONL dataset and summary.
- `tests/`: unittest tests, also discoverable by pytest.
- `../configs/features.yaml`: bounds, sampling interval, window size, peer profiles.

No new dependency is introduced. PyYAML==6.0.2 and pytest==8.3.4 are already pinned
in `infra/requirements/services.txt`. Target service runtime is Python 3.11 in
`infra/Dockerfile.services`. Unprivileged tests also run on the existing Mint
Python 3.12. The authoring workspace used Python 3.12.14 and unittest; pytest is
not installed there, so a pytest run is not claimed.

## Exact Feature contract and operational definitions

The dictionary contains exactly these fields, with no new fields or nullable
placeholders. Invalid data produces a separate quality record and no Feature.
Interpretations below are explicit measurement definitions; these are not a claim
that OpenFlow statistics provide complete application connection records.

| Field | Definition |
|---|---|
| timestamp_ns | Collector's monotonic receipt time at the end of the measurement window |
| window_s | Actual duration covered by retained whole measurement intervals |
| host, role | Validated hospital inventory identity and role |
| flow_count | Distinct outgoing observed tuple/rule groups with activity in the window |
| unique_dst | Distinct configured destination hosts in those groups |
| unique_dst_ports | Distinct observed TCP/UDP destination port numbers; other protocols have no port |
| bytes_out, pkts_out | Positive deltas in forwarding-rule counters at the source access switch |
| bytes_in, pkts_in | Those same source-side deltas attributed to their destination host |
| new_peers | Distinct outgoing peers first seen, or seen again after history TTL, during the window |
| off_allow_list_flows | Outgoing observed groups whose destination is absent from the configured peer profile |
| short_flows | Active outgoing groups with at least one rule-age observation at or below short_flow_age_s |

**Short-flow definition:** `short_flows` is a short-rule-age proxy, not the number
of completed short connections. Rule duration is not connection lifetime. An
observation-only tuple has unknown age and is not counted as short. Likewise,
`flow_count` counts observed transport/rule groups, not TCP sessions. Non-TCP/UDP
protocols are grouped by source, destination and protocol; ICMP type/code are not
separate feature groups. These definitions must stay attached to training data.

Critical allows can wildcard the transport source port. A specific packet-in tuple
covered by that rule is coalesced into its rule group. A group seen only through
packet-ins still contributes to destination/port/fan-out features, but adds no
invented bytes or packets. Counter and observation packet totals are never added.
Port-wildcard coalescing uses a constant number of indexed lookups per tuple.

`bytes_in` and `pkts_in` mean attempted forwarding at the source, **not confirmed
receipt**. A downstream drop can prevent delivery. PacketOut first packets, rules
created and removed entirely between polls, and counter resets can reduce coverage.
Use the independent clinical echo probes for service delivery measurements.

`new_peers` uses a bounded, per-process 60-second last-seen history by default.
There is no network history before collector startup. History resets on controller
epoch changes; gaps invalidate windows, but the retained known-peer history is
still only observed history. `off_allow_list_flows` is peer-based, not port-based.
The profile is provisional: changing it changes feature semantics. It never adds
ACLs or makes an isolation decision.

## Windows and quality

- Poll every nominal second. A counter interval is accepted only once all five
  access switches have advanced their completed poll vector. Core/transit copies,
  ARP, table-miss entries and priority-40000 drop counters are excluded.
- Source attribution is recomputed using configured IP, access DPID and ingress
  port; a telemetry row's supplied host label is not trusted.
- First valid snapshot is a baseline. Do not import historical cumulative totals.
  A newly observed rule can start from zero only if its earliest possible creation
  follows the preceding acquisition. Otherwise rebaseline.
- Reject stale/incomplete snapshots, malformed counters, long poll gaps, overlapping
  acquisition intervals, generation changes, decreasing counters/durations,
  disappearing rule instances, guard drops and missed observation sequences.
- A rejected interval clears all pending windows. Baseline and then warm up again.
  Rule expiry can therefore suppress features even for otherwise idle hosts. This
  conservative behavior is deliberate; it must not be relabeled as normal traffic.
- Default target window is five seconds. Retain whole intervals rather than
  prorating bursts. Actual duration can exceed five seconds by at most one accepted
  interval; use `window_s` for rates. Boundaries describe collector receipt time;
  staggered counter acquisition is not a simultaneous packet trace. Every feature
  record includes start/end acquisition ranges for each source switch.
- Feature JSON retains the exact contract; `quality` and derived rule-hit rates
  live beside it. `quality.valid` means the available streams passed these checks,
  not that every network packet or connection was observed.
- The collector writes quality statuses even when no feature is emitted. A future
  detector must reset or pause anomaly streaks on invalid windows, and must never
  label missing samples as benign. Sustained guard activity can leave the extractor
  unable to emit valid windows; a separate pressure/fan-out response is future work.

## How to verify this works

All commands below start from the repository root in a normal terminal (`$`).
Keep the updated custom controller running on loopback ports 16653/18080.

### 1. Unprivileged tests

```bash
/usr/bin/python3 -m unittest discover -s decision/tests -v
```

Expected: 33 tests, OK (18 feature/collector tests plus 15 detector/policy tests). They include real local HTTP requests and JSONL/Event output.
They do not require Mininet, Docker, sudo, Ryu, or a live controller.
For the pinned services environment with pytest installed:

```bash
python -m pytest decision/tests -q
```

Target Python 3.11 check using the existing services image, if not yet built:

```bash
sudo docker build -t hospital-services:lab -f infra/Dockerfile.services infra
sudo docker run --rm --network none -v "$PWD:/repo:ro" hospital-services:lab \
  python -m unittest discover -s decision/tests -v
```

This validates the separate service runtime; it does not rebuild or stop Ryu.
The local HTTP test runs within its own loopback interface, with no external network.

### 2. Start the clinical traffic in another terminal

```bash
sudo /usr/bin/python3 topology/hospital.py --traffic configs/clinical.yaml
```

Leave it at `mininet>`. The configured workers last 60 seconds. Start collection
promptly while the workers are active; the extractor needs a baseline and at least
five seconds of usable intervals. Do not run pingall or the load probe during this
first arithmetic/attribution gate.

### 3. Collect features from a normal terminal

```bash
/usr/bin/python3 -m decision.collect_features --samples 15
```

It prints `features_started` with a unique output path, then `features_summary`.
The dataset is written under `artifacts/features/<run_id>.jsonl`, which is gitignored.
Do not paste the angle-bracket example path into the terminal: use the actual path
printed by the command if inspecting the full file. Existing files are never overwritten.

Expected acceptance for a clean active C1 run:
- At least one valid window for all 24 configured hosts.
- `latest_features` includes the three monitors; each has central_mon as a peer,
  UDP destination port 18001 and positive outgoing rule-hit deltas while traffic runs.
- Exactly 14 Feature fields; separate quality metadata identifies the profile and scopes.
- Fresh acquisitions, no unexplained resets or guard/sequence gaps during valid windows.
- Forwarding-rule rates should be consistent with the offered 10 Hz monitor probes,
  allowing first-packet omission and acquisition-boundary uncertainty. Do not demand
  an invented exact count from an arbitrary five-second window. Clinical echo logs
  remain the independent source for probe delivery and RTT.

A run with no valid windows exits nonzero and still saves quality records. Read the
`sample_statuses` and `invalid_reasons`; do not disable checks to get a passing demo.
Close Mininet with `exit` after collection. The feature collector exits by itself.

## Polling delay, storms and process ownership

This module performs GET requests only and never shifts or deletes switch rules.
It retains the existing controller's full-packet transport, software guard and
rate/capacity limits; it does not claim to solve upstream packet-in overload. Its
state is bounded by configured rows, observations and segments, and by the fixed
24-host peer inventory. No arbitrary source-key history grows from packets.

Five-second windows reduce noise but delay availability at startup and after gaps.
The next feature cut occurs only after new polls; a fast scan can contact all hosts
before that cut. Observation tuples supplement fan-out visibility at window boundaries;
this is **not** a sub-second event-driven detector. A separately evaluated pressure
or fast-path detector, adaptive polling, and named always-on clinical-floor variants
remain future work, not changes silently applied to B0/B1/B3.

Future containment budget: poll alignment + initial window warm-up when needed +
(N-1) window steps + measured feature time + inference + policy + REST + confirmed
installation. Here `poll_received` brackets data arrival and `features_ready` records
actual completion. The other stages do not exist yet; worst-case time-to-contain
remains unbounded. Poll/guard gaps can indefinitely postpone a valid feature.
Report hosts touched/infected before a future action honestly in scenario evaluation.

One asyncio collector coroutine owns baselines, windows and peer history. Ryu owns
actual switch connections/counters and shares no memory with it. HTTP is offloaded
through the existing bounded client. Each run has one exclusive JSONL writer and
its own ID. No SQLite, reconciler, TTL writer, policy state or action retries are
introduced. Those require their own concurrency and invariant tests in later modules.
HTTP has per-I/O timeouts, not a guaranteed total deadline against a trickling peer.
The finite sample count is not a hard wall-clock runtime guarantee.

## Self-review and known limits

- No safety invariant is modified: no action or rule-write path exists.
- Feature/Event field names are unchanged. Proxy definitions and peer profile are
  explicit, versioned measurement semantics, not claims of full connection visibility.
- Guard/eviction gaps produce invalid windows, not zero-valued normal samples.
- Tests exercise no mutation endpoints, validate finite bounds and cover the actual
  HTTP/file path. No live Mint extraction, ML accuracy or containment delay is invented.
- Service preservation after the accounting patch was user-verified separately:
  see `../docs/features-handoff-2026-10-26.md` for the exact run and limits.


The separate fan-out detector and role-policy planner are documented in [DETECTION.md](DETECTION.md). That module emits proposals only; controller enforcement is not connected.

## Live integration

See [LIVE.md](LIVE.md) for the finite live runner, action confirmation, censored
feature handling, and remaining real-switch verification. Current decision suite: 42 tests.
