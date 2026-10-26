> Updated 2026-10-26: Python 3.9 uses the Bookworm image after Bullseye
> package downloads returned 404s. Mint 22.2 is the active student environment.
> See ../docs/verified-progress.md for user-reported tests. The automated
> network smoke test below has NOT yet run on that laptop.

# Infrastructure: install, verify, preserve evidence

## Design Analysis

1. **Requirement restated:** Prepare an Ubuntu/Mint lab with separate Ryu
   Python 3.9 and services Python 3.11 environments. Verify OpenFlow 1.3,
   forwarding, priority precedence, hard expiry and disconnected-controller
   behaviour before building hospital-specific policy.
2. **Assumptions:** Dedicated Ubuntu 22.04/24.04 or Mint 22.x lab, 4 vCPU, 8 GB RAM, approximately
   25 GB free disk, sudo and internet access for initial installs. Ryu uses a
   virtualenv inside a container rather than a host virtualenv. Mininet is the
   explicitly allowed fallback. No existing repository is modified.
3. **Failure modes and risks:** Old Ryu/eventlet dependencies can fail imports;
   ports can be occupied; Docker/OVS may not run in nested environments; package
   repositories and image tags may change. Root-level Mininet operations require
   an isolated lab. The read-only preflight and image build checks fail visibly.
4. **Options considered:** Native interpreters avoid containers but require extra
   OS installation sources. Separate containers preserve runtime isolation.
   Containernet is the preferred later emulator, but Mininet gives a smaller
   first validation target. Host networking is Linux-specific and lets OVS reach
   the loopback-only controller without publishing it on the LAN.
5. **Decision and justification:** Use containers for Python runtimes and host
   OVS/Mininet. The services container checks dependencies and runs tests; it is
   not a fake decision API. The Ryu container runs upstream simple_switch_13
   strictly as an infrastructure probe.
6. **How we test and measure:** Unit tests reject invalid priorities, external
   controller addresses, invalid ports and unbounded/non-expiring quarantine.
   The VM test verifies forwarding, exact synthetic UDP allow rules above a
   source quarantine drop, critical UDP after disconnect, and hard-timeout
   expiry. Meter installation is reported separately. JSON observations use
   monotonic_ns; they are infrastructure observations, not project Event records.

## VM recipe

Create an Ubuntu 22.04 VM with 4 CPUs, 8 GB RAM and at least 25 GB free disk.
Use NAT for dependency downloads; do not attach the lab switch to a physical NIC.
Take a VM snapshot before installation. Copy/extract this directory into your VM.
Run all commands below from the extracted hospital-sdn directory.

The setup script accepts Ubuntu 22.04/24.04 and Mint 22.x (Ubuntu noble base). On the existing Mint laptop, Docker, OVS and Mininet are already installed; do not rerun setup merely to continue working.
It does not silently alter your existing four-host lab or install third-party
Python PPAs. Docker commands use sudo; no Docker group membership is added.

## Exact verification commands

### 1. Install host packages and check prerequisites

```bash
bash infra/setup.sh --install
sudo /usr/bin/python3 infra/preflight.py
```

Expected: all preflight checks true and exit code zero. A failure is a stop
condition; resolve it before running the network smoke test.

### 2. Build and test the two separate Python runtimes

```bash
sudo bash infra/lab.sh build
sudo bash infra/lab.sh run --rm services-check
sudo bash infra/lab.sh run --rm services-check python -m pytest -q -p no:cacheprovider infra/tests
```

Expected: image builds complete, services runtime reports PASS, and six tests
pass. Ryu image construction imports app_manager, WSGI and simple_switch_13,
which checks more than merely importing the top-level ryu package.

### 3. Start the smoke controller

```bash
sudo bash infra/lab.sh up -d ryu
sudo bash infra/lab.sh ps
sudo bash infra/lab.sh logs --tail=80 ryu
```

Wait until the Ryu container is healthy. It listens on VM loopback port 16653,
chosen to avoid the usual 6653/6633 ports used by other labs.
Health means the TCP listener exists, not that the OpenFlow handshake works;
the next command verifies the handshake.

### 4. Run the isolated network test

```bash
mkdir -p artifacts
set -o pipefail
sudo /usr/bin/python3 infra/smoke.py | tee artifacts/network-smoke.jsonl
```

Expected final observation: network_smoke PASS. Required preceding checks:
baseline_forwarding PASS, critical_allow_over_drop PASS,
disconnect_and_expiry PASS. meter_installation can be UNSUPPORTED; that result
means future policy must use allow-list-only restriction until meters are
validated. Installation alone does NOT demonstrate accurate rate limiting.

The test creates one uniquely named switch and two hosts with no external links.
It verifies a synthetic UDP echo service, not hospital C1-C5. Rules use explicit
output ports because this topology has one switch; OFPP_NORMAL is not used for
these test allow rules. The legacy learning-switch baseline uses its own normal
learning logic; this is not the project's final forwarding implementation.

The synthetic permanent allow is an explicit exception to the requirement that
containment rules expire. The source drop has a hard timeout. The test disconnects
only its own switch from Ryu, then verifies the allow remains and the drop expires.
It does not terminate a controller that could be serving another lab.

Cleanup runs on success, ordinary failures, Ctrl-C and SIGTERM. SIGKILL or a VM
crash can leave resources behind; use a VM snapshot/reboot or inspect the unique
hs-prefixed bridge before removing it. Never blindly run mn -c while another
lab is active.

### 5. Capture versions and stop the smoke controller

```bash
sudo bash infra/lab.sh run --rm ryu pip freeze > artifacts/ryu-resolved.txt
sudo bash infra/lab.sh run --rm services-check pip freeze > artifacts/services-resolved.txt
sudo bash infra/lab.sh images
dpkg-query -W docker.io openvswitch-switch mininet > artifacts/host-packages.txt
sudo bash infra/lab.sh down
```

Use the actual image ID shown by Compose with `sudo docker image inspect IMAGE_ID` if recording image metadata.
Direct dependency versions and Python image versions are pinned. Transitive
dependencies, OS apt packages and image digests are NOT fully locked yet.
Retain these manifests after the first successful build; do not describe the
environment as bit-for-bit reproducible until all those inputs are locked.

### Local unit tests without containers

```bash
python3 -m unittest discover -s infra/tests -v
python3 -m compileall -q infra
bash -n infra/setup.sh infra/lab.sh
```

These do not prove Docker builds or network behaviour. On the VM, the setup
installs pytest too, so `/usr/bin/python3 -m pytest -q infra/tests` also works.

## What still needs the real VM smoke test

- Python 3.9/eventlet 0.30.2/Ryu 4.34 compatibility and package availability.
- Docker image builds, loopback binding and OpenFlow negotiation.
- Actual OVS priority, timeout, secure-mode behaviour and meter capabilities.
- Mininet cleanup and resource use on the specified 4 CPU / 8 GB machine.

The old Python 3.9/eventlet environment is retained to test the requested legacy
compatibility constraint. It should remain a contained lab dependency, not be
described as a supported production security stack.

## Engineering gates for subsequent layers

**Storms:** This learning-switch smoke test has no storm guard and must not run
S1. The controller implementation must measure packet-ins/s, CPU and missed
polls, verify buffering and controller-port metering rather than assume support,
and implement bounded counters, make-before-break updates, scoped strict deletes,
staggered expiry and a circuit breaker. Choose the storm acceptance threshold
from a measured VM capacity baseline; no throughput result exists yet.

**Polling:** With poll interval T and confirmation count N, a provisional bound
is T + (N-1)*window_step + feature + inference + policy + REST + installation.
It is a bound only when execution times, queues and observation assumptions are
bounded. Map attack_start to poll_received for initial alignment,
poll_received to features_ready, then scored, decision, rule_requested and
rule_installed. The existing Event fields do not isolate every transport cost;
use details or explicitly propose extra instrumentation before claiming that
they do. last_malicious_packet needs independent traffic/ground-truth observation.
Fast-path fan-out, adaptive polling and tiered restrictions belong in the actual
controller and decision layers. Always-on critical allow-lists require a named
experimental variant. Report infection before detection honestly.

**State ownership:** Future desired state belongs to FastAPI, actual rule state
to Ryu. REST requests require idempotency and per-host sequencing; use per-host
serialization, lease expiry, reconciliation and a single SQLite WAL writer.
This delivery has no action API, policy state or database, so those properties
are not implemented or tested here.

## Unresolved policy decisions (not silently implemented)

- PROTECT requires an identified attacker; the existing Action contract names
  one host but no distinct malicious-source field. Resolve its semantics before
  implementing it, with an explicit contract diff if a field is needed.
- Human override cannot both force arbitrary isolation and preserve immutable
  critical flows. Default to preserving the critical rules pending a decision.
- B3a rate limits must affect the high-priority allowed traffic, not merely a
  lower-priority rule that never matches it.
- B3b existing-session preservation needs connection state; a plain stateless
  OpenFlow five-tuple rule is not proof of an established session.
- ARP and reverse-direction service rules must be designed explicitly for the
  hospital topology. This test uses static ARP only to isolate the IPv4 checks.
- Keeping critical rules after controller process loss is testable here;
  persistence through a switch restart requires a separate recovery design.

## Self-review

No Feature, Score, Action or Event contract changed. No hospital safety policy is
claimed as implemented. Unit tests exercise infrastructure guards; the network
test attempts to override a synthetic critical allow and verifies timeout expiry.
The test owns its unique bridge/hosts, uses bounded subprocess calls and cleans
up its UDP child process. No global flow-table deletion or machine-wide Mininet
cleanup is performed. Explicit outputs are suitable only for this single-switch
smoke network. Further policy, concurrent release/escalation, stale action,
restart and clinical-safety tests are required with their respective layers.

## Primary documentation checked

- https://ryu.readthedocs.io/en/latest/getting_started.html
- https://docs.openvswitch.org/en/stable/faq/openflow/
- https://github.com/containernet/containernet

Documentation is design evidence, not confirmation that this exact VM has
passed the checks. No papers or experimental results are cited.
