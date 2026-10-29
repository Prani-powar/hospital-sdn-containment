# Hospital SDN Containment — EL Project

**SDN-Based Microsegmentation for Automated Threat Containment**

A student research prototype that emulates 24 hospital computers/devices, detects
suspicious fan-out and selects containment according to device role. Use only
harmless synthetic traffic in the isolated lab. No real patient data is involved.

## Open or run the project

**[Open the public browser demo](https://medseg-hospital-console.shadyowl16.chatgpt.site)** — no installation, works on Windows and phones.

**[Start here: team setup, local website and real Linux lab](docs/START_HERE.md)**

The current source branch is **feature/hospital-topology**. To run just the local
website: `py -3 start_dashboard.py` on Windows or `python3 start_dashboard.py` on
Linux/macOS. This opens the UI; real Mininet experiments require the Linux lab.

## Current status

| Component | Implemented / measured status |
|---|---|
| Hospital topology | 24 hosts, six OVS switches, 29 links; student reported 552/552 pings |
| Custom Ryu forwarding and telemetry | Built and run on Mint; six connected switches and fresh counters reported |
| C1 monitor service and timed restriction demo | Student reported PASS; 393/393 probes across measured phases, unrelated ping blocked during restriction |
| Features and detector | Real source-ingress extraction and deterministic threshold scoring; local tests pass; no trained ML model |
| Role policy | ISOLATE office/guest; RESTRICT clinical/IoMT/vendor; source-attributed PROTECT for servers |
| Authenticated enforcement | Implemented allows-before-drops, barriers, exact readback, strict release and TTL; fake-switch tests pass; student supplied one combined reception1 PASS; broader cases pending |
| Live runner | Implemented finite observe/enforce pipeline; separates desired, pending, failed and confirmed status |
| Clinical C1–C5 workers | Implemented; all 13 sources tested with local UDP echo; student supplied a C1–C5 PASS in one combined OVS run; broader cases pending |
| Finite demo runner | Implemented; validates without root and records phases with owned cleanup; student supplied PASS: reachable → blocked → reachable, 860/860 counted C1–C5 replies |
| Interactive dashboard | Guided simulation, evidence import, local telemetry and fresh decision status; hosted animations are simulation |
| Automated ML and research evaluation | Not complete; no invented accuracy, latency or clinical-safety results |

**141 portable Python tests pass in the authoring workspace**, plus UI logic checks.
A student-supplied Mint run reported combined reception1 containment/release and
860/860 C1–C5 replies during its three measured phases. This is one controlled
run, not a production safety claim. Broader source/action, restart and load
experiments remain pending. No trained ML model or comparative accuracy is claimed.

## Start here

- [Remaining work and measured-results exporter](docs/EVALUATION.md)
- [Finite demo runner](docs/DEMO.md)
- [Earlier implementation checkpoint](docs/implementation-status-2026-10-26.md)
- [Windows-friendly team tasks and mentor demonstration](docs/TEAM_NEXT.md)
- [Local dashboard and evidence viewer](dashboard/README.md)
- [Live detector-to-controller runner](decision/LIVE.md)
- [Confirmed enforcement design and limits](controller/ENFORCEMENT.md)
- [Detector and role policy](decision/DETECTION.md)
- [Environment and infrastructure](infra/README.md)
- [Contribution workflow](CONTRIBUTING.md)

From the repository root, with Python and PyYAML available:

```bash
python3 scripts/check.py
```

These checks do not need Mininet, Ryu or root. Running the actual emulation needs
the Mint/Linux lab. Friends on Windows can work on the dashboard, pure Python
modules, test cases, evidence analysis and presentation material.

## How the pieces connect

Mininet creates independent network namespaces; OVS switches connect them through
virtual links. Ryu owns OpenFlow forwarding and switch-rule transactions in its
Python 3.9/eventlet container. A separate Python process reads bounded loopback
telemetry, extracts features, scores behavior and proposes role-specific actions.
An explicitly enabled, authenticated action API applies timed rules and confirms
installation using barriers plus actual rule-table readback. The local website
shows fresh status and recorded events; it does not receive the action secret.

| Directory | Purpose |
|---|---|
| topology/ | Hospital inventory, finite C1 traffic and restriction demonstration |
| controller/ | Ryu app, telemetry, resource bounds and opt-in action transactions |
| decision/ | Features, threshold detector, role planner, replay and live runner |
| dashboard/ | Interactive simulation, evidence import and local read-only bridge |
| configs/ | Validated topology, traffic, feature, detector and enforcement settings |
| infra/ | Pinned compatibility environment, setup and smoke checks |
| scripts/ | Combined portable check command |
| docs/ | Design, evidence, limitations and team handoff |

C2–C5 use synthetic lab service ports. Their local echo workers have been tested;
one student-supplied combined OVS run also reports successful phase-scoped delivery. Live clean-window release/vendor escalation
is suppressed under containment because drop rules censor normal observations;
the initial live variant uses TTL and scoped release. See the live guide for
restart/ownership limits and explicit reconciliation behavior.

## Team ML and evaluation tooling

See [ML pipeline](docs/ML_PIPELINE.md) and [lab evaluation runbook](docs/LAB_EVALUATION_RUNBOOK.md) for the teammate branch additions. M1/M2 scores require reviewed local training data; no trained lab model is bundled. Persistent lab startup is documented in [PERSISTENT_LAB.md](docs/PERSISTENT_LAB.md).

Research implementation: [experiment runbook](docs/RESEARCH_RUNBOOK.md) and
[threat model / dataset card](docs/THREAT_MODEL_AND_DATASET.md). Real benchmark
numbers remain pending Linux/OVS execution; generated plans are not results.

For learned detection without a labelled attack-training dataset, see the
[standalone Isolation Forest workflow](docs/ISOLATION_FOREST.md): collect normal
lab runs, calibrate on separate seeds, then start the persistent lab with M1.
