# Custom Ryu controller: forwarding, telemetry and opt-in enforcement

Default operation remains telemetry-only. The optional authenticated action layer
is documented in [ENFORCEMENT.md](ENFORCEMENT.md). It adds bounded role-aware
transactions with barriers and rule-table readback. The live decision runner is
in [../decision/LIVE.md](../decision/LIVE.md). New real-switch verification is
pending; historical sections below describe the earlier telemetry baseline.

Current local test totals: **38 controller tests**, **42 decision tests**, and
**28 topology tests**. Six image-build Ryu tests are defined but have not been
run in this authoring workspace. The previous four-test image passed on Mint.

## Design Analysis

1. Requirement: forward the static flat-L2 hospital with OpenFlow 1.3,
   collect source-attributable flow counters every nominal second and expose
   operational state to a separate service.
2. Assumptions: the previously verified hospital-ryu:lab image is present; the
   topology is the configured six-switch tree with fixed IP/MAC attachments.
   The runtime remains Python 3.9 with eventlet 0.30.2. The eventual decision
   service is a separate Python 3.11 process and communicates through HTTP.
3. Risks: packet-in storms, partial stats, late replies, reconnect counter
   discontinuities, unbounded rule/state growth and blocked OpenFlow send queues.
4. Options: MAC learning/flooding versus configured routes; broad MAC matches
   versus transport-specific IPv4 matches; all-switch versus access-only stats;
   buffering/truncation versus full packets with explicit workload limits.
5. Decision: configured output ports, address/port-specific IPv4 forwarding,
   deterministic ARP forwarding, bounded admission and rule budgets, jittered
   expiry, staggered access-switch polls and a loopback-only read API.
6. Test/measure: 22 unprivileged tests, four real-Ryu adapter tests during image
   build, followed by live all-pairs ping, C1 service traffic, the existing
   restriction test, REST inspection and a separately named finite load test.

## Files and interfaces

- app.py: Ryu/eventlet adapter, OF1.3 handlers, polling and WSGI.
- core.py: validated settings, static fabric, token buckets, rule budget,
  multipart cache and ingress attribution; independently testable without Ryu.
- telemetry_client.py: async read-only wrapper for another process. It uses
  bounded executor calls, with slots retained through cancelled callers.
- inspect.py: health, poll quality, counter-attribution and sampled CPU output.
- storm_probe.py: finite harmless UDP workload restricted to configured lab peers.
- smoke_ryu.py: real Ryu parser/adapter/Response checks in the Python 3.9 image.
- ../configs/controller.yaml: rates, timeouts, state limits and policy version.

| Endpoint | Behaviour |
|---|---|
| GET /v1/health | 200 when all six switches and fresh bounded polls are present; otherwise 503 with details |
| GET /v1/stats | 200 with explicit complete/fresh/truncated metadata, even when data is incomplete |
| GET /v1/topology | Configured inventory and links |

In the original telemetry baseline there were no write endpoints. The opt-in
write API is now documented in ENFORCEMENT.md. TelemetryClient.get_stats rejects incomplete or
stale results by default. This read-only client is not the future full
ControllerClient mutation contract; push_rule/remove_rule and their
idempotency/reconciliation semantics are intentionally not supplied as stubs.
Feature/Score/Action/Event contracts are unchanged.

## How to verify this works

Run these from the repository root in the normal terminal, not at mininet>.
Close the previous Mininet session before replacing its controller.

### 1. Unprivileged tests

```bash
/usr/bin/python3 -m unittest discover -s controller/tests -v
```

Expected: 22 tests pass. These include actual local HTTP requests and async
cancellation tests. They do not import Ryu or require root.

### 2. Build the new controller

```bash
sudo docker build -t hospital-controller:lab -f controller/Dockerfile .
```

This uses the locally built hospital-ryu:lab compatibility image. It copies
source/configuration without reinstalling dependencies and runs four adapter
tests against actual Ryu objects. If this gate fails, send the complete error.
The adapter tests serialize real OpenFlow messages but do not emulate a switch.

If teammates have not built that base image yet, use:

```bash
sudo docker build -t hospital-ryu:lab -f infra/Dockerfile.ryu infra
```

The base tag is mutable. Record its image ID/digest before experiments; this is
not a fully locked reproducible software supply chain. Dependency pins are in
../infra/requirements/ryu.txt and the actual resolved versions must be retained.
The legacy Python/eventlet combination remains confined to this lab.

### 3. Replace the old learning-switch process

If the old hospital-ryu-controller is still running, stop that specific
container from the normal terminal:

```bash
sudo docker stop hospital-ryu-controller
```

If it is already stopped, Docker may report no such container. Do not stop
unrelated containers. Start our controller and leave its terminal open:

```bash
sudo docker run --rm -it --network host --name hospital-custom-controller hospital-controller:lab
```

It uses loopback OpenFlow port 16653 and loopback REST port 18080. No elevated
container privileges or Docker socket mounts are needed. There is no API auth;
loopback binding is intentional for the single-machine lab.

### 4. Connect and test the hospital

In a second normal terminal:

```bash
sudo /usr/bin/python3 topology/hospital.py
```

At mininet>:

```text
pingall
```

Expected: 0% dropped, 552/552 received. Inspect health in a third normal terminal:

```bash
/usr/bin/python3 -m controller.inspect --samples 3 --interval 1
```

Allow the first polls to finish. Expected: six connected switches,
telemetry_complete true, counters increasing and no OpenFlow errors.
Health does not certify link availability or medical-service health by itself.
Close the topology with exit before the next run.

### 5. C1 and restriction regression

```bash
sudo /usr/bin/python3 topology/hospital.py --traffic configs/clinical.yaml --restrict-demo configs/restriction-demo.yaml
```

Expected: restriction_demo PASS, preservation in the measured phases, positive
drop counter, automatic expiry, recovery and clean teardown. This result has
not yet been measured with the new controller in the authoring workspace.

For independent counters inspection, run the interactive C1 mode instead:

```bash
sudo /usr/bin/python3 topology/hospital.py --traffic configs/clinical.yaml
```

In another normal terminal while traffic is active:

```bash
/usr/bin/python3 -m controller.inspect --samples 5 --interval 1
```

Expect ingress rows for active source monitors and central_mon. For raw fields:

```bash
/usr/bin/python3 -c "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:18080/v1/stats',timeout=2)),indent=2))"
```

## Challenge 1: storms, state bounds and rule shifts

Specific normal matches include ingress port, Ethernet/IP endpoints and IP
protocol. TCP/UDP add both ports; ICMP adds type/code. Each new service tuple
therefore reaches the controller before a forwarding rule exists. ARP is
routed to the configured target, without broadcast flooding or learned-MAC state.
Unknown sources/addresses, unexpected source attachments and fragmented IPv4
are rejected; IPv6/VLAN/dynamic host discovery are outside this module.

The full-packet table-miss uses OFPCML_NO_BUFFER deliberately: known lab OVS may
not buffer packets, and truncated unbuffered data cannot faithfully forward the
first application packet. The parser examines at most 256 header bytes, but the
OpenFlow connection still receives the original full packet. Buffered packet-ins
are handled when present. Buffering and miss_send_len are not claimed to have
reduced load in this version.

Global and per-source token buckets open a short software guard on exhaustion.
This drops new packet-ins; existing switch rules keep operating. The guard acts
after Ryu receives the message, so it is NOT a dataplane packet-in rate cap or
proof against transport/parser overload. Opening a guard can drop new legitimate
flows, including clinical traffic that has no installed allow. Measure that cost.
Switch/controller-port meters remain optional and unverified; this module does
not pretend an application guard replaces them.

Normal FlowMods have a rate budget, idle timeout 30s and hard timeout 120..150s.
Stable traffic avoids constant relearning; hard-expiry jitter reduces synchronized
misses. Conservative per-switch leases cap normal rules at 1024 even when polls
fail. Exhausting installation capacity permits budgeted PacketOut forwarding,
with repeated packet-ins and explicit counters; it does not grow an install queue.
The lease capacity can undercount free space after early expiry/deletion, which
is a conservative availability/performance trade-off.

No flow deletes are issued, including at reconnect. Retaining normal rules avoids
bulk-expiry storms and preserves existing external priority-50000 clinical rules.
Changed static routing is not supported live: close/rebuild the lab for a new
topology. This module never writes above normal priority 10000. The miss rule
is priority 0. Future containment must use make-before-break, scoped cookies,
strict deletion and barrier-confirmed evidence; it is not implemented here.

Send-queue waits use a bounded eventlet timeout and report failures. Queuing a
FlowMod is not evidence of switch installation. Request rows and multipart
parts are bounded; only completed requests are published. Missing/overflowed/
late responses become explicit incomplete telemetry. API row truncation also
makes complete false. A stalled or overloaded system has no guaranteed polling
latency despite the nominal 1s setting.

### Separate storm-capacity gate (not a research attack scenario)

Open an interactive hospital network without containment or clinical floor
rules. Record approximately idle load first with controller.inspect. Then in a
third normal terminal start the sampler:

```bash
mkdir -p artifacts
/usr/bin/python3 -m controller.inspect --samples 12 --interval 1 > artifacts/controller-storm.jsonl
```

While that sampler runs, at mininet>:

```text
reception1 /usr/bin/python3 -m controller.storm_probe --host=reception1 --rate 500 --duration 10
```

All peers are from the configured hospital; binding the configured source IP
normally requires execution inside that host namespace. There is no infection,
spreading or real external scan. The command reports actual offered rate.

Provisional acceptance on this laptop: at least 90% of ten steady-load samples
have complete telemetry; no switch disconnect or OpenFlow error; source/global
guard counters are visible; steady-load CPU stays below 80% of one core.
These thresholds are design gates, not measured results. Inspect raw switch
snapshots for request/receive time and rule counts, and sample process CPU/maxRSS.
If a gate fails, report the offered rate and measured capacity, then tune and
repeat. Do not claim 500 or 1000 packets/s is safe before measuring it.
process_max_rss_bytes is peak resident memory, not current RSS.

## Challenge 2: polling delay and feature visibility

Polls are staggered across the five access switches; the core is not polled by
default. Source counters are attributed only at the source's access switch,
avoiding transit copies. Both directions are visible as independently sourced
flows. The next extractor can derive incoming traffic from destination fields;
it must account for incomplete coverage.

Counters are cumulative, not rates or Feature windows. Generations and a
controller epoch identify reconnect/restart discontinuities. Per-flow duration,
cookie and match must also be checked before subtracting counters. The first
packet forwarded via PacketOut may not appear in its new rule's counters, and
traffic removed between polls can be missed. Source-ingress packet-ins are
therefore a separate sequence-numbered ring, not silently added to flow totals.
Consumers track sequence gaps/eviction and must not treat lost observations as
normal traffic. Bounded observation retention is not a durable dataset.

Fast-path fan-out counters could consume these ingress observations before a
1s poll, but no threat threshold or automatic action exists yet. Adaptive polls
and tiered restrictions are deferred to detector/decision integration. The guard
is a resource control, not an ML verdict. The separate C1 restriction test
installs an explicit protected floor; it is not a default controller baseline.
Always-on IoMT/server policies need their own named evaluation variant.

For future N-window containment, budget:
alignment + stats delivery + (N-1)*window_step + feature + inference + policy +
REST + confirmed switch installation. At nominal T=1s the alignment target is
up to 1s; it is not a hard guarantee under load. Stats replies after 2.5s are
rejected rather than treated as current. Feature/inference/policy/action timings
are not implemented and have no invented numeric bound. Worst-case containment
time in this telemetry-only module is unbounded because it does not contain.

requested_ns/received_ns bracket stats acquisition. Later poll_received,
features_ready, scored, decision, rule_requested and rule_installed Event stages
must be tied to real process/switch evidence. Hosts infected before containment
and sensitivity to T and N remain measurements for evaluation, not hidden costs.

## Challenge 3: process ownership and concurrency

Ryu owns datapath connection identity and observed switch state. Its eventlet
handlers/monitor use no standard threading or blocking HTTP client. Bounded
state updates and API snapshot copies contain no cooperative yield. Send calls
may yield under backpressure, so replies and disconnects are validated against
the current datapath object and request XID. Old connection events cannot clear
new connection state; reconnect resets snapshot generations.

The separate async telemetry client offloads standard-library HTTP to a bounded
executor admission scheme. It has per-I/O timeouts and response-size limits;
it does not claim a malicious trickling response has a hard total deadline.
Cancelled callers retain their worker slot until completion, preventing unlimited
background HTTP work. Caller task/backlog limits belong to the future service.

Desired containment state, per-host serialization, idempotent/versioned actions,
actual-rule reconciliation, TTL renewal and SQLite WAL single-writer ownership
are still required in the next controller action and decision modules. There is
no shared Ryu/FastAPI memory and no SQLite or policy state in this increment.
The client never retries writes, because no writes exist. Do not infer safe
release/escalation races or restart reconciliation from these telemetry tests.

## Self-review and known limits

No medical device/server is automatically isolated. No clinical allow is
deleted or overridden by this app. This is not a complete clinical safety
implementation: C2-C5 policies and mutation-invariant tests are still needed.
With a controller failure, existing externally installed critical allows remain
in OVS and timed test restrictions expire; new normal tuples may lose forwarding
after normal rules expire. Switch restart recovery is a separate problem.

State/resource limits are explicit; no learned MAC table or arbitrary source-key
cache grows from network input. Polls retain only their current completed and
pending snapshots. Normal-cookie hashes identify forwarding rules but are not
cryptographic IDs or a substitute for future action idempotency.

Unit tests cover routing, source attachment, match prerequisites, cookies,
expiry/capacity, multipart atomicity, overflow, missed/late polls, reconnects,
HTTP limits, degraded health and async cancellation. Image-build tests exercise
actual Ryu serializers and WSGI Response objects. Real switch negotiation,
forwarding, service preservation and load capacity still need the Mint checks.

Primary sources checked: Ryu's app_manager.py, controller.py, hub.py,
ofproto_v1_3_parser.py and the official simple-switch/monitor/REST examples:
https://github.com/faucetsdn/ryu
https://book.ryu-sdn.org/en/html/rest_api.html
https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html


## Accounting and observation continuity update

Design analysis for this increment:
1. Requirement: distinguish forwarding admission limits and let readers detect lost observations.
2. Assumptions: static matches, one controller process, unchanged normal/clinical priorities.
3. Risks: duplicate packet-ins over-reserve slots; renewed leases expire out of order;
   a reader can mistake a full ring for complete observation history.
4. Options: raise limits, release on potentially stale statistics, or retain conservative
   leases keyed by the entire match. Choose the last option.
5. Decision: each distinct normal match has one renewable reservation per switch.
   Replacements retain capacity even at the cap. Expiry scans are bounded by the configured
   cap; failed sends and reconnects do not release reservations early. Add separate
   rate/capacity counters and a per-reader observation cursor.
6. Validation: 22 local tests; four image-build adapter tests now also check duplicate
   reservations and the separate admission counters. Rebuild and repeat Mint checks.

`normal_install_budget_exhausted` remains the aggregate of the two admission reasons
for compatibility. New counters `normal_flow_mod_rate_limited` and
`normal_rule_capacity_exhausted` explain which limit was reached. A denied rate token
reserves no capacity; a denied capacity reservation sends no FlowMod. Replacements
renew the conservative lease using maximum hard timeout plus send-queue timeout.
This is controller admission accounting, not confirmed OVS occupancy. Queued sends
can still have switch/channel delivery delay; no installation deadline is guaranteed.
The cap does not include external rules or rules inherited from a different process.
No capacity is reclaimed optimistically from idle-timeout guesses or partial stats.

`/v1/stats.complete` still describes flow-counter snapshots only. It does not certify
packet-in history. Additive `observation_guard_drops` and `observation_scope` fields
make the scope explicit. A reader owns its own `ObservationCursor` and calls
`cursor.read(stats)` on successive responses. The result includes new observations,
missed sequence count, controller epoch change, and guard-drop deltas. A first read
starts from sequence zero for that controller epoch, so prior evictions and drops
are reported. Subsequent reads deduplicate records. A restart invalidates continuity.
A reader that cannot accept missing data must invalidate the affected feature window;
this increment provides the signal, not a feature extractor or detector.

`controller.inspect` now prints `observation_continuity` alongside flow snapshot
completeness. `continuity_ok` refers only to admitted source-ingress packet-in sequence
coverage and the reported guards since that reader's last sample. It does not mean
all packets or flows were observed: installed rules bypass packet-ins, and invalid,
unsupported or truncated packets are counted separately. Guard counts measure
packet-ins, not unique flows or clinical packet loss. The ring stays bounded at 512
records by default. Consumers must poll fast enough or explicitly handle gaps.

For the controlled Mininet probe, use `--host=reception1` with the equals sign.
Mininet substitutes a standalone node-name argument with an IP address, which the
probe correctly rejects as an unknown configured host name. Start the sampler anew
if a probe fails before sending traffic.

Self-review: normal forwarding priority and critical allows are unchanged. No new
containment writes or shared asyncio/eventlet state were introduced. One Ryu-owned
bounded lease map is updated without yielding; REST readers only copy snapshots.
One-second stats alignment and software-only guards retain the previously documented
latency and channel-load limits. Observation gaps remain explicit rather than hidden
by increasing buffers. Live performance improvement has not yet been measured.
