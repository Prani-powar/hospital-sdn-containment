# Hospital SDN Containment — EL Project

**SDN-Based Microsegmentation for Automated Threat Containment**

Four-student research prototype: detect suspicious behaviour in an emulated
hospital network and contain hosts according to their roles while preserving
specified clinical services. Simulation only; use harmless scenario traffic.

## Current status

| Component | Status |
|---|---|
| Mininet + OVS connectivity on Mint 22.2 | User verified |
| Ryu 4.34 / Python 3.9.23 / eventlet 0.30.2 | User verified Bookworm image build and startup |
| OpenFlow 1.3 connection to Ryu | User verified, 0% ping loss |
| Temporary IPv4 source drop and timeout recovery | User verified |
| TCP allow rules above a source drop | User verified HTTP 200 while ping showed 100% loss |
| Automated infrastructure smoke test | Provided; not yet run on student laptop |
| 24-host hospital, custom controller and decision service | Planned |
| ML detection, live dashboard and evaluation | Planned |

The upstream learning switch is an infrastructure probe. Automatic detection,
complete safety invariants and production readiness are not implemented.

## Start here

- [Environment and verification commands](infra/README.md)
- [Verified progress and limitations](docs/verified-progress.md)
- [Team contribution guide](CONTRIBUTING.md)
- [Implementation roadmap](docs/roadmap.md)

From the repository root, local checks are:

```bash
python3 -m unittest discover -s infra/tests -v
bash -n infra/setup.sh infra/lab.sh
```

Follow infra/README.md to build containers and run the isolated network smoke
test. The student's existing Ryu container uses port 16653: finish that lab and
stop that controller before starting Compose's controller on the same port.
The services image checks dependencies; it does not yet serve a decision API.

## Repository architecture

| Directory | Purpose |
|---|---|
| infra/ | Implemented environment definitions, checks and smoke tests |
| topology/ | Planned hospital topology, service traffic, scenario runner |
| controller/ | Planned custom Ryu app, REST, flow stats, storm guard |
| decision/ | Planned role policy, state machine, expiry and reconciliation |
| ml/ | Planned role baselines, features and anomaly models |
| dashboard/ | Planned live topology, critical health and event timeline |
| eval/ | Planned multi-seed experiments and metrics |
| configs/ | Planned shared hospital/policy configuration |
| docs/ | Progress, roadmap and design records |

Future directories will be added with their modules. Research results and
clinical safety guarantees are not claimed.
