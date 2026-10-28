# Hospital topology: first runnable module

This module creates the specified 24 hosts, five access switches and one core.
It uses the permitted Mininet fallback; Containernet is not implemented here.
The shared network definition is ../configs/hospital.yaml.

## Design Analysis

1. Requirement: generate the hospital's flat L2 network from configuration.
2. Assumptions: Linux Mint's system Python can import Mininet and YAML; local
   Ryu already listens on 127.0.0.1:16653. Existing upstream simple_switch_13
   provides baseline forwarding only.
3. Risks: duplicate addresses, interfaces that exceed Linux's name limit,
   resource collisions, disconnected switches and partial startup failures.
4. Options: hardcoded topology versus validated YAML. YAML lets the four team
   members share a single inventory and role mapping.
5. Decision: validate before privileged operations; deterministic MACs, DPIDs
   and switch ports; explicit short host interfaces; a loop-free switch tree.
6. Acceptance: 24 hosts, 6 switches and 29 links; every switch negotiates
   OpenFlow 1.3 and all 552 directed host pairs pass baseline ping.

## Exact commands

Run from the repository root in a normal terminal. No ZIP download is needed.
Validation creates no network and needs no sudo:

```bash
/usr/bin/python3 topology/hospital.py --validate-only
/usr/bin/python3 -m unittest discover -s topology/tests -v
```

Start Ryu in a separate terminal if it is not already running:

```bash
sudo docker run --rm -it --network host --name hospital-ryu-controller hospital-ryu:lab ryu-manager --ofp-listen-host 127.0.0.1 --ofp-tcp-listen-port 16653 ryu.app.simple_switch_13
```

The hospital-ryu:lab image was previously built on the student's Mint laptop.
New teammates should first follow ../infra/README.md to build the Compose
images instead. Run one controller at a time on port 16653.

Launch the hospital:

```bash
sudo /usr/bin/python3 topology/hospital.py
```

At mininet> run these individually:

```text
nodes
net
reception1 ping -c 3 -W 1 ehr
monitor1 ping -c 3 -W 1 central_mon
pingall
exit
```

Expect both short pings and pingall to show 0% loss. pingall attempts 552
directed pairs; allow it to finish. This is baseline reachability, not policy
validation. For an unattended baseline test that exits automatically:

```bash
sudo /usr/bin/python3 topology/hospital.py --ping-all
```

Successful startup emits topology_ready and host_mapping JSON observations.
These infrastructure observations intentionally do not change the project's
Event schema. No attack/detection/containment timestamps are claimed here.

Optional pinned development environment (not required on the prepared laptop):

```bash
python3 -m venv .venv-topology
.venv-topology/bin/pip install PyYAML==6.0.2 pytest==8.3.4
.venv-topology/bin/python -m pytest -q topology/tests
```

Use system Python for live emulation so the apt-installed Mininet is visible.
The authoring workspace uses PyYAML 6.0.3; a run on a second YAML version is not
claimed. Record dpkg package versions and YAML version for experiment manifests.

## Scope and constraints

- Segment names are groups of access ports, not VLAN enforcement. Flat L2 is
  intentional. All hosts are reachable before containment is implemented.
- Host names follow the project specification: ehr, not ehr1.
- No NAT, physical NIC attachments, default internet routes, real scans,
  infection agents, clinical services or containment rules are added.
- Clinical server/device roles are labels only at this layer. The eventual
  controller and policy engine must enforce the medical safety invariants.
- Both connection checks and OVS preflight calls are bounded. Existing bridge
  and interface names cause startup to fail rather than adopting another lab.
- Cleanup runs after ordinary errors, normal CLI exit and SIGTERM. A SIGKILL,
  abrupt power loss or Mininet failure inside its own cleanup may leave
  resources. Inspect them before removal; never run global mn -c during another lab.
- Controller-loss behaviour and storm capacity are not evaluated by this
  baseline. The learning switch's full-packet table-miss and broad MAC rules
  must be replaced before scan experiments.
- The code changes none of the Feature/Score/Action/Event contracts.

## Verification and self-review

Unit tests verify the inventory, tree connectivity, distinct IP/MAC/port mappings,
interface lengths, local controller, bounded waits, OpenFlow 1.3/secure switches,
and rejection of invalid roles, duplicated YAML keys and invalid addresses.
A recording test double checks generated calls; it does not prove Mininet's
kernel behaviour. Live startup, cleanup and baseline ping must run on Mint.

No isolation decisions, permanent clinical allow rules or quarantine rules are
installed by this module. No HTTP calls, policy queues, SQLite writes or shared
Ryu/FastAPI state exist yet. Their concurrency and safety tests belong to later
modules. No measured performance or attack-containment claim is made.

Primary API references checked:
https://mininet.org/api/classmininet_1_1link_1_1Link.html
https://github.com/mininet/mininet/blob/master/mininet/net.py
