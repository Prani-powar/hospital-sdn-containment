# Live detector-to-controller pipeline

`decision/live.py` connects the real feature extractor, deterministic detector,
role planner and controller action client. The default is observation only.
It is a finite, single-owner asyncio command rather than a web backend; the local
read-only dashboard reads its atomic status snapshot. No new Python dependency is
required beyond the repository's existing PyYAML requirement.

The runner uses bounded loopback HTTP, fixed 24-host state, a 24-proposal outbox,
a 256-event ring, exclusive per-run JSONL output and at most 3600 polls. Its events
preserve the shared Event fields. The atomic status file is
`artifacts/decision-status.json`; the dashboard rejects snapshots older than five
seconds, from a different controller epoch, or marked stopped. The hosted simulation
cannot reach a laptop's localhost. Use the local dashboard for real lab data.

Observe example, from the repository root in a normal terminal:

```bash
python3 -m decision.live --samples 600
```

Only after the real-Ryu and controlled OVS validation gates pass, enable the action
API in the controller environment with `HOSPITAL_ENABLE_ACTIONS=1` and the same
strong `HOSPITAL_ACTION_TOKEN` used in the decision process, then run:

```bash
python3 -m decision.live --enforce --samples 600
```

There is no secret in a URL, browser, repository or status snapshot. This document
contains setup instructions for later use; no live process was started on the
user's laptop by the authoring workspace.

A decision is desired state, HTTP acceptance is pending, and only the controller's
filtered readback produces a confirmed installation. Failed or ambiguous HTTP
writes halt mutations without retry. A 409 busy response is retried using exactly
the same proposal because the controller did not reserve it. Confirmations have a
20-second deadline. A changed controller epoch, previous planner actions or a
controller event gap halts writes for explicit reconciliation. There is no automatic
lease takeover across process restarts. Stop competing runners; one process should
own the default status path. A failed run does not remove unrelated rules.

## Censored evidence and release

Drop rules prevent subsequent malicious packets from becoming normal PacketIns.
The current feature extractor intentionally excludes quarantine-drop counters.
Therefore quiet contained windows cannot prove clean behavior or persistent vendor
attacks. Live mode suppresses clean-window release and vendor escalation while a
host's desired lease is active. It requests scoped release at lease expiry instead.
Offline planner fixtures still test their separate K-clean/vendor policy logic;
those fixtures do not prove safe live clean-release or escalation.

The detector is threshold based, not a trained ML model. A critical-server anomaly
without separately attributed malicious source remains review-only. Clinical probe
delivery is not inferred from scores, floor readback, counters or animations.

## Validation and limits

42 decision tests include seven live-pipeline tests with the actual detector and a
fake action transport. They cover observe-only behavior, pending versus confirmed,
TTL versus censored clean windows, busy versus ambiguous writes, epoch/ownership
conflicts, action failure, atomic status and Event contracts. Controller tests use
stateful fake switches and actual local HTTP; real Ryu/OVS verification is pending.
Source-ingress features, nominal one-second polling and finite evidence history
retain their documented visibility and overload limits.
