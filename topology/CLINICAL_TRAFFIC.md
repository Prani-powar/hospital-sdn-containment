# C1 monitor traffic: synthetic UDP service

This increment adds harmless application probes from monitor1-3 to central_mon.
It covers C1 only; C2-C5 services, attacks, ML and containment remain future work.
It extends the existing topology module without changing Feature/Score/Action/Event.

## Design Analysis

1. Requirement: measure delivery and round-trip time for the monitor service.
2. Assumptions: the 24-host topology and Ryu baseline already pass reachability.
   UDP port 18001 is a configurable synthetic lab choice, not a clinical standard.
3. Risks: startup races, dropped replies, stale replies, orphan processes and
   unbounded logs could invalidate measurements.
4. Options: ICMP reachability versus an application service; UDP echo provides
   a concrete protocol and destination port to preserve with future allow rules.
5. Decision: 10 probes/s/source, sequence/run/source validation, exact reply and
   peer checking, bounded timeouts, finite duration and file-backed logs.
6. Test/measure: configuration/message tests, real local UDP exchange, timeout,
   process cleanup and status aggregation tests. Live Mininet remains a separate
   integration check. Report actual sent/received counts and measured RTT.

## Run one step at a time

Use the normal terminal, from the repository root, with Ryu still running:

```bash
/usr/bin/python3 -m unittest discover -s topology/tests -v
sudo /usr/bin/python3 topology/hospital.py --traffic configs/clinical.yaml
```

Startup emits c1_started with the log directory. At mininet> wait a few seconds
and run:

```text
sh /usr/bin/python3 topology/clinical.py status
```

Expect three c1_status JSON lines, one per configured monitor. success_rate
1.0 means every completed probe received its matching reply. Initial startup
loss is possible and is retained in the metrics; inspect actual counts.
No probes means success_rate null, not a healthy status. The displayed rate is
the cumulative success fraction for completed probes, not a throughput estimate.

Traffic stops after 60 seconds by default. The CLI stays open. Later status
calls then show the completed run rather than ongoing traffic. Exit the CLI
and relaunch to run a new 60-second measurement. Do not interpret an old
successful record as proof the service is currently running.

At mininet> finish with:

```text
exit
```

The launcher stops only its child workers before tearing down the network.
It emits c1_worker_stopped and topology_stopped; logs remain under the existing
git-ignored artifacts/clinical/RUN_ID directory.

## Measurements and limitations

- Three probes per 100 ms nominally: 30 requests/s and 30 replies/s overall.
  Scheduling and packet loss can reduce the observed rate.
- Each JSON probe records monotonic timestamp, sequence, success and RTT.
  Requests and replies share a sequence/run identifier. Only an exact reply
  from the expected peer counts as successful.
- This measures round-trip service success, not one-way delivery or latency.
  An echoed request proves an application round trip; patient data is simulated.
- File logs and metrics accumulate only for a finite configured run (maximum
  300 seconds, eight sources, 20 probes/s/source). The status reader uses constant
  running totals, but loads one bounded log file's text at a time.
- No automatic archive retention is imposed; remove old experiment outputs
  deliberately once they have been saved as required.
- The echo service validates JSON and identifiers for measurement consistency.
  It provides no cryptographic authentication and must remain inside the lab.
- Baseline learning-switch rules are still broad MAC rules. This increment
  installs no critical allow rule and makes no clinical-safety guarantee.
- SIGTERM/Ctrl-C invoke cleanup; SIGKILL or power loss cannot guarantee cleanup.
  Status includes completed per-probe records. Interrupting mid-probe can make
  its completed-record count differ from the worker's final attempted count.

## Verification and self-review

Message parsers reject malformed/oversized/wrong-run records; invalid roles,
unknown hosts, duplicate sources, out-of-range rates and unbounded durations
are rejected. Tests use real UDP loopback plus a controlled stuck-process test.
They do not prove namespace behaviour or preservation during actual containment.
Finite log growth, bounded startup, no catch-up bursts and ownership of child
processes are explicit. No policy/concurrency/lease contracts change here.

The launcher now disables propagation of Mininet's existing console logger to
the root handler, addressing duplicate terminal output. Verify this on Mint.

Primary API reference:
https://mininet.org/api/classmininet_1_1node_1_1Node.html
