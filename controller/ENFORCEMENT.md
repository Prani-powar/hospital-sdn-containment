# Confirmed, timed lab enforcement

This opt-in increment adds actual OpenFlow action code. It has not yet been
verified on the team's Mint/OVS installation. Stateful fake-switch tests prove
coordinator behavior, not real packet delivery. Existing telemetry-only runs
remain available with actions disabled.

## Design analysis

1. Requirement: authenticated role-aware containment, preserved synthetic clinical
   services, timed rules, scoped release, and switch-confirmed installation.
2. Assumptions: the fixed six-switch tree and source attachments; one Ryu owner;
   separate decision process; no real patients or production hospital network.
3. Risks: partial multi-switch writes, stale epochs, ambiguous HTTP responses,
   unsupported source attribution, censored features, and clinical allow conflicts.
4. Options: fire-and-forget FlowMods or bounded barriers plus filtered rule-table
   readback. Use the latter; no successful write response alone implies installation.
5. Decision: one active transaction, a fixed host inventory, versioned proposals,
   authenticated loopback POSTs, make-before-break exceptions, source ingress first,
   exact-cookie strict cleanup, and hard timeouts. No automatic indefinite renewal.
6. Validation: 38 unprivileged controller tests and six real-Ryu adapter tests
   defined for image builds. The six image tests are pending here because the
   compatible runtime is unavailable. Actual OVS forwarding remains a separate gate.

## Action boundary

`GET /v1/actions` reports bounded action status and the latest 256 events.
`POST /v1/actions` accepts the planner's versioned proposal wrapper containing the
unchanged Action contract. Requests require a 32–256 ASCII-character Bearer token,
fresh connected telemetry, a matching controller epoch and confirmed clinical floor.
Bodies are limited to 16 KB. The token stays in process environments, never the UI.
HTTP 202 means pending; only a matching `confirmed` result means rule-table readback
matched the compiled rules. GET status is a historical confirmation, not a fresh
read of every installed rule on each request.

The actor starts only with `HOSPITAL_ENABLE_ACTIONS=1` and a valid
`HOSPITAL_ACTION_TOKEN`. It owns permanent priority-50000 C1–C5 synthetic service
rules. These use explicit forward/reverse ports and are verified before accepting
action requests. C1 is UDP 18001; C2–C5 use UDP 18002–18005 respectively. C2–C5 are
configured synthetic flows; their application delivery is not yet measured.
The existing C1 test used a different experimental variant: label results separately.

ISOLATE is limited to admin/guest/vendor, with bidirectional IPv4 drops at priority
40000 and specific management exceptions at 45000. RESTRICT supports IoMT/clinical/
vendor, preserving configured service peers and dropping other outbound IPv4.
PROTECT drops only traffic from a separately attributed source to a critical server;
a conflict with a protected pair is rejected. Server anomalies alone do not identify
an attacker and therefore require review. IPv6/VLAN/spoof-resistant isolation is not
claimed. This remains a static lab, not production network security.

Timed exceptions outlive timed drops by 20 seconds. Drops have a maximum 40-second
hard timeout; transactions have a 15-second deadline. Failed partial operations are
reported as failed and are not blindly retried. Timed drop rules expire without the
controller. Permanent floor rules survive controller failure, but switch restart
loses them until successful recovery. Recovery and service delivery need measurement.

The transaction order is inspect owned rules → exceptions → barriers → drops →
barriers → strict cleanup of old owned rules → barriers → exact filtered readback.
Every batch registers all datapaths and XIDs before any cooperative send may yield.
Replies validate connection identity and current XID. Disconnects, errors, late
replies, row overflow or wrong readback cannot produce `rule_installed`.
Release deletes only exact table/match/priority/full-cookie identities in the host's
containment namespace. No wildcard deletion or deletion of priority-50000 rules.

## Runtime ownership, latency and limits

Ryu/eventlet alone owns OpenFlow requests, 24 latest host results, one active job,
and a 256-event ring. Work per tick and FlowMod rates are bounded. Action polls are
separate from telemetry request IDs. The Python decision process uses bounded
executor HTTP calls; cancelled callers retain their slot until the worker ends.
No asyncio/SQLite state is shared with eventlet. Audit JSONL has one process writer.
A new planner cannot take over an old planner's leases silently: the finite runner
halts writes if it finds existing actions or a changed controller epoch. Reconciliation
is deliberately explicit; process restart is not claimed to resume previous leases.

Normal PacketIns still carry full packets. Application guards act after reception
and do not protect transport/parser capacity. The protected clinical floor reduces
first-flow dependence only for its exact configured service tuples. It is not a
controller-port meter or a general overload proof. Staggered nominal 1-second polls
plus feature-window startup, N-window evidence, HTTP, transaction scheduling and
readback determine latency; no hard containment-time claim has been measured.

## Self-review and remaining verification

Tests include idempotency/content conflicts, stale versions, wrong epochs/owners,
partial reads, strict replacement/release, protects/restrictions, allow-before-drop,
synchronous-reply races, cancellation and real local HTTP error handling.
A complete lab gate must still build the six Ryu tests, exercise C1–C5 delivery
before/during/after each supported action, verify unrelated traffic is blocked,
restart controller/switches, and record actual stage timestamps and load capacity.
No automated ML model, malware-spread result or production safety claim is made.
