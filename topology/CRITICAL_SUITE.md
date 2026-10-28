# Five synthetic clinical services

The C1–C5 suite starts 13 finite UDP echo clients and five server workers inside
the configured Mininet hosts. It uses the exact endpoints and ports from the
named enforcement floor, so the traffic test and policy cannot silently disagree.
These are synthetic UDP probes, not implementations of real medical protocols.

| Flow | Sources | Server | UDP port |
|---|---|---|---:|
| C1 | monitor1, monitor2, monitor3 | central_mon | 18001 |
| C2 | pump1, pump2 | ehr | 18002 |
| C3 | imaging1 | pacs | 18003 |
| C4 | nurse1–3, doctor1–3 | ehr | 18004 |
| C5 | lis | ehr, with matching echo replies | 18005 |

## Design analysis

1. Requirement: measure actual application replies for all configured critical
   services before, during and after containment, with per-source evidence.
2. Assumptions: static isolated topology; the existing UDP worker can be reused;
   no patient data; 18 owned processes are acceptable for this finite lab.
3. Risks: matching the wrong flow/run, stale logs, partial startup, missing workers,
   incomplete records and confusing loopback tests with switch preservation.
4. Options: separate protocol implementations versus tagged synthetic echo workers.
   Use tagged workers; don't claim real DICOM, HL7 or infusion-device behavior.
5. Decision: exact named floor, C1-compatible packets, distinct C2–C5 packet identity,
   bounded rate/duration/log reads, per-run directories and owned cleanup.
6. Validation: six new tests, including all five real local UDP worker sessions.
   These prove local echo behavior, not actual OVS preservation; the live lab gate
   remains pending. Existing C1 tests remain unchanged and pass.

The default configuration sends five probes per second per source for 90 seconds,
with an 80 ms reply deadline and no catch-up bursts. This is offered load, not a
promise of achieved rate or latency. No traffic targets leave the configured lab.

For later lab use, the existing interactive topology accepts:

```bash
sudo /usr/bin/python3 topology/hospital.py --critical-suite configs/critical-suite.yaml
```

This mode is separate from --traffic, --restrict-demo and --ping-all. Workers stop
before Mininet teardown even on partial startup errors. The old C1-only mode still
works. Validate the plan without privileges using --validate-only or:

```bash
python3 -m topology.critical_suite
```

Probe logs preserve run/flow/source identity and exact-echo RTT. Phase summaries
exclude outside-window records, reject duplicate or malformed records, and require
at least half the nominal number of probes plus zero observed loss for PASS. That
coverage gate tolerates scheduling variation; it is not an availability SLA or
medical safety standard. Missing evidence is not healthy traffic.

The finite demonstration in scripts/demo.py writes fresh recent-interval clinical
snapshots for the local dashboard and retains complete phase reports. Every source
must contribute real replies. All five configured services and ordered confirmed
actions are required for a containment PASS. See ../docs/DEMO.md.

## Self-review

The C1 packet format and event names remain compatible. New flow identities reject
cross-service echoes. Cleanup targets only owned processes. Readback of clinical
allow rules is never substituted for application delivery. Source attachment,
source spoofing, real clinical protocols and overload guarantees retain the lab's
existing limits. The new workers have not yet been run through the team's OVS.
