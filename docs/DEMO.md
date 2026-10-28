# Finite mentor demonstration

The new runner packages the existing lab pieces into a bounded demonstration.
Its code and validation checks are ready; its actual Docker/Ryu/OVS execution has
not been performed in this workspace. Nothing was started on the student's laptop.

## What the runner does

1. Refuses occupied lab ports and requires the already-built controller image.
2. Starts one uniquely named owned controller container. It generates a token in
   the controller and decision process environments, never in command arguments,
   report files, the browser, dashboard process or synthetic host workers.
3. Verifies that the HTTP listener's epoch belongs to that container's startup log.
4. Builds the configured 24-host Mininet network and starts all five synthetic
   clinical services: 13 client workers plus five servers.
5. Waits for healthy telemetry and, in enforcement mode, confirmed clinical rules.
6. Starts the finite decision process and local read-only dashboard.
7. Records a baseline, generates a harmless reception1 fan-out at four packets/s
   for 16 seconds, and waits for actual confirmed ISOLATE and then RELEASE.
8. Measures unrelated ping and all critical services in baseline, restricted and
   recovered phases. Saves report.json and owned logs under artifacts/demo/RUN_ID.
9. Uses one experiment run ID across clinical workers, decision events and action requests.
   The attack_start record explicitly means observed probe-process launch, not an
   invented first-packet measurement.
10. Stops its owned workers, topology, container, decision process and dashboard.
   It does not stop an existing controller by name or delete unrelated OVS rules.

The runner is finite: the local dashboard closes when the demonstration finishes.
The report remains available and can be imported into Verified evidence afterwards.
Occupied ports cause refusal, not automatic shutdown of other work.

## Commands for later use

The user does not need to run these while development continues. Plan validation
works without Mininet, Docker, root or Linux:

```bash
python3 scripts/demo.py --validate-only --enforce
```

Once the new image's six Ryu checks have passed in the Linux lab, a single command
starts the controlled real enforcement demonstration:

```bash
sudo /usr/bin/python3 scripts/demo.py --enforce
```

Without --enforce it is an observation-only experiment, and its report says
OBSERVATION_ONLY only when its measured baseline/recovery clinical checks pass
and the owned fan-out worker completes without send errors. Missing or failed
evidence still produces FAIL. It cannot claim containment PASS. The runner deliberately does
not download dependencies or rebuild an image silently. The controller Dockerfile
must first be built from the current checked-out source. An old image may start
but fail the new action/floor readiness gate.

## Evidence shown to mentors

Open http://127.0.0.1:8088 on the lab laptop while the runner is active and choose
live mode. The browser shows fresh telemetry, detector scores, pending/failed/
historical installation ACKs, and recent C1–C5 probe replies. The web UI sends no
action secret and cannot itself install or remove rules.

Afterwards, open the dashboard separately and import the run's report.json in
Verified evidence. Both the old three-monitor restriction report and the new
13-source report are supported. Imports stay local and are labelled user-provided,
not independently verified. The hosted view supports the updated simulation explanations and local report
imports, but cannot reach a laptop's localhost. Its existing private access is
preserved.

PASS requires all 13 sources across five services with nonzero successful probes,
valid ping results (reachable → blocked → reachable), and distinct confirmed
ISOLATE/RELEASE proposals ordered between the measured phases. Queued requests,
empty logs, ping command errors and stale confirmations cannot count as success.
FAIL retains diagnostics. No successful live result is bundled or invented.

## Validation and limits

137 Python tests pass locally, including real loopback UDP workers, real HTTP
bridge requests and fake-switch enforcement. Node UI logic checks also pass;
these are not browser layout or real switch tests. The runner's privilege-free
plan and evidence/ownership tests passed; the real runner remains a lab gate.

The detector is threshold based. Censored clean windows do not drive automatic
clean-release or vendor escalation. This demonstration exercises one office host's
ISOLATE/TTL release, not all supported actions, source spoofing or malware spread.
Actual latency, capacity, clinical continuity through OVS, switch/controller restart
and broader role/action experiments still require controlled measurement.

The runner now also exports a reassessed Markdown/CSV summary when its report and
audit files are readable. See EVALUATION.md for evidence and timing limits.

## Choose a different attack source

The finite runner now defaults to `--host=random`. It selects an office or guest
endpoint and excludes the source recorded by the previous real invocation.
`--validate-only` does not update that history. Select a specific source with:

```bash
sudo /usr/bin/python3 scripts/demo.py --enforce --host=billing1
sudo /usr/bin/python3 scripts/demo.py --enforce --host=monitor2
```

Office and guest hosts use ISOLATE. Explicit clinical, IoMT and vendor sources
use RESTRICT, preserving configured service exceptions and the C1–C5 floor.
Critical-server selections are available as visual review scenarios only: this
runner refuses to isolate a critical server and does not invent an attributed
source for PROTECT. These new varied-source real runs still need Mint validation.
The previously supplied successful run was reception1 only.

The dashboard's Attack source selector supports all 24 visual scenarios and
shows a terminal command for supported real runs. It does not remotely start a
root process or install malware. Stop a separately running dashboard before
launching the finite runner, which owns port 8088 during its experiment.

The attacker skull is a persistent scenario/evidence marker, not a malware
scanner. Simulated containment and release do not clear it; local browser storage
preserves it until the user clears it or changes the simulation source. Clearing
it does not disinfect a machine or change OpenFlow rules. Live suspicion flags
are separate from simulation markers and persist through a subsequent no-alert
score/release; missing telemetry is not shown as healthy evidence. Traffic probes
remain finite. Older reception1 reports still import; new reports identify the
selected source and expected role-specific action.

## Explain detection and review the device

The dashboard shows destination count, destination-port count, off-profile groups
and consecutive suspicious samples. Live values come from fresh decision features
and actual configured thresholds/streaks. Missing, stale or invalid windows remain
unavailable; traffic hidden by containment cannot establish that a host is clean.
The threshold detector is not an infection scanner.

The guided simulation uses a selectable attacker delay (12, 25 or 40 seconds),
then a five-second traffic window, a second suspicious sample ten seconds after
probing starts, and containment twelve seconds after probing starts. These are
illustrative teaching times, not measured latency. Real rolling windows refresh
about once per second and overlap; two samples do not necessarily mean ten
seconds. Critical servers stay review-only when source attribution is absent.

The communication table shows 13 C1–C5 source paths alongside the affected source's
blocked unrelated connection. Simulation numbers are labelled illustrative. Live
rows require fresh clinical request/reply evidence; loss and unmeasured states
are explicit. Action ACKs are historical readback, not proof a timed rule remains
active. No claim covers every unrelated connection.

The guided scenario stops at containment and waits for review. Review evidence,
acknowledge its limits, then choose still suspicious (keep the flag) or record a
remediation assessment (restore simulation access). This is a user-declared
assessment, never an antivirus result or independently verified clean state.
The marker is not cleared by a low score or timeout. Reviews are local UI state
and do not mutate live rules. The finite real runner retains bounded timed rules
and automatic cleanup; live release can occur independently while suspicion
remains flagged. Endpoint forensic verification is outside the website's scope.

## Spatial map and explicit restoration

The charcoal/orange console puts individual device paths first. Green dashed
paths show simulated clinical request/reply traffic (or fresh measured replies
in live mode), red fan-out paths grow as off-profile contacts accumulate, and
contained endpoint icons move into a separate bay. This is a picture of logical
policy separation, not a physical change to topology. Blocked probe paths stop at
the boundary. Clinical/IoMT restriction preserves the green allowed-service paths.
Critical-server review does not move or isolate a server. Live historical ACKs
alone do not move a node or prove a timed rule is currently active.

Choose **Problem resolved** and confirm your assessment to return the simulated
host to green, its original position and normal traffic. Red probing paths and
the attacker marker disappear. The label is **NORMAL · USER RESOLVED**; it is a
user declaration, not an antivirus scan. Live review remains read-only and cannot
change real controller rules. The public website and the repository contain the
same interface, with the network data source visibly labelled.

The team's separate Human Override panel and loopback authenticated POST bridge
are retained in this redesign. These controls are distinct from the simulation's
Problem resolved button, require live mode and an action token, and are subject
to the controller's proposal contract and ownership checks. Their live end-to-end
validation remains separate; restoring the visual simulation does not invoke them.
