# Repeatable C1 preservation test

This is a functional rule test in the disposable emulated network. It does not
detect an attack, use the future policy engine or implement experimental B3.
It adds an explicit protected-service floor, so do not mix its results with B0
or claim a clean detector-versus-containment baseline comparison.

## Design Analysis

1. Requirement: preserve monitor1 → central_mon UDP service while another flow
   from monitor1 is restricted, then verify automatic drop expiry and recovery.
2. Assumptions: topology, C1 probes and local Ryu already work. Use the configured
   synthetic UDP port, current normal forwarding and Mininet fallback.
3. Risks: stale results, a timed-out rule, command errors or absent traffic can
   falsely suggest successful preservation.
4. Options: manual commands versus one automated before/during/after run. The
   automated run checks both fresh application records and the switch counter.
5. Decision: derive explicit output ports from the topology; install all 18
   bidirectional C1 allow rules first at priority 50000; read them back; add a
   priority-40000 source restriction on the target's ingress switch, TTL 10s.
6. Acceptance: baseline/control ping passes, restricted ping exits 1 and the
   active drop counts at least two packets, all three monitors meet the
   configured fresh-probe count and success fraction in each phase, drop
   disappears and control ping recovers. Persist failure evidence too.

## Run

From the repository root, in the normal terminal, with Ryu already running and
the previous Mininet session closed:

```bash
/usr/bin/python3 -m unittest discover -s topology/tests -v
sudo /usr/bin/python3 topology/hospital.py --traffic configs/clinical.yaml --restrict-demo configs/restriction-demo.yaml
```

The run is automatic; there is no mininet> prompt in this mode. Allow roughly
20–40 seconds on the working laptop, but no measured completion time is claimed.
Before/during/after records print as restriction_phase. The final success record
is restriction_demo status PASS; failures have status FAIL and the launcher exits
nonzero. Afterwards the workers and topology are stopped automatically.

The emitted report path is:
artifacts/clinical/RUN_ID/restriction-report.json

Inspect that actual run's report and worker logs. A failed command or test is
evidence to investigate; never edit it into a passing result.

## Rule semantics and safety scope

- C1 requests match source IP, destination IP, UDP and destination port.
  Replies match server IP, monitor IP, UDP and server source port. Reply
  destination ports are ephemeral, so these allow rules do not lock one
  client process's ephemeral port.
- Explicit output actions follow the tree on the medical access, core and
  server access switches. OFPP_NORMAL is not used.
- Critical allows have no timeout and no delete operation is exposed by this
  test. They remain until the disposable switches are torn down by Mininet.
  This is the explicit critical-rule exception; all restrictions have hard TTLs.
- The target is a configured IoMT C1 source. It is restricted, not fully
  isolated: its C1 traffic and ARP remain available. Other protocols and
  isolation bypasses are not exhaustively evaluated.
- The ingress restriction is verified before measuring it. In this topology
  each host has one access attachment; no propagation is needed for this
  functional test. The actual controller will need general enforcement logic.
- OVS commands run without shell expansion, with timeouts and scoped cookies.
  Protected rules are added and confirmed before the restriction. There are
  no wildcard deletes or DELETE+ADD replacement of normal forwarding rules.
- The test does not claim that its allow rules cannot be changed by an external
  administrator. Immutability within the future engine needs separate tests.
- Exact-cookie readback plus drop packet counters are required. Expiry is
  observed by polling, so expiry_observed_ns is an observation time, not an
  exact switch enforcement timestamp. Rule readback is not a FlowMod/barrier
  timing benchmark.
- No standalone ovs-ofctl barrier command is used. Its monitor-only
  ofctl/barrier command is not a general CLI command.

## Metrics and limitations

Each phase includes the bounded ping check and a configured measurement wait.
Application records are assigned by completion timestamp. The first reply in a
phase may have been sent just before its boundary; that boundary effect must be
considered before using these measurements in a paper.

The configured acceptance fraction is 1.0 after warmup. This may fail on a loaded
laptop; preserve the result and inspect load or timing rather than silently
relaxing the requirement. Timing and command delays can exhaust the finite C1
run. Stopped workers explicitly fail the test; old successful samples do not pass.

Table-miss storms and 1-second detection latency are not exercised: this test
creates low-rate service probes and ICMP controls, with no detector. It makes no
claim about detection delay, spread prevention or capacity. It also does not
address cross-process Ryu/FastAPI state: no REST action API or policy engine is
implemented. Those layers still require storm, latency-budget, reconciliation,
idempotency and lease tests.

## Self-review and tests

Tests check forward/reverse output ports, protocol/port/address-specific allows,
priority ordering, timed ingress drops, role/timing guards, exact cookies, fresh
phase records, failure on stopped workers, persisted reports, correct ping-error
interpretation and rejection of zero-match drops. A controlled runner double
checks decision evidence; actual OVS and namespace enforcement require the Mint
run. No shared Feature/Score/Action/Event contract changes.

Primary CLI reference:
https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.html
