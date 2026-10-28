# Team work and honest mentor demonstration

The project emulates a hospital network: 24 Linux network namespaces act as hosts,
six OVS switches forward traffic, and a Ryu controller programs forwarding rules.
The website is a view of that system. Hosted guided animations are simulation;
real telemetry and detector/action states require the local lab bridge.

## What is ready in source

- Hospital topology, fixed addressing, clinical C1 synthetic UDP service and timed
  restriction demonstration, previously measured on Mint.
- Custom forwarding/telemetry controller, feature extraction, threshold detector,
  role-aware planner, authenticated timed enforcement transactions and finite live
  orchestration. New enforcement/runtime verification is currently local fixture
  and fake-switch testing, not a completed real-switch experiment.
- Interactive dashboard with simulation, evidence import, read-only telemetry and
  fresh decision status. Installation ACK is historical; it does not prove ongoing
  clinical delivery or current containment after TTL expiry.

## Tasks teammates can do on Windows

| Owner | Concrete contribution | Linux required? |
|---|---|---|
| UI teammate | Test guided simulation; test override panel (token input, role notes, ack checkbox) in demo mode; improve mobile layout | No |
| Python teammate | Run controller/decision pure tests, add policy edge cases and audit JSONL summaries | No, use Python and PyYAML |
| Evaluation teammate | Prepare result tables with run IDs, offered rate, N/T settings, actual timestamps and evidence status | No |
| Presentation teammate | Explain topology, threat signal, role-specific action, C1 preservation, human override and limits; prepare mentor script | No |
| Mint operator | Build Ryu image; verify new actions against actual OVS; test override panel in live mode with HOSPITAL_ACTION_TOKEN | Yes, for this lab runtime |

Work from feature/hospital-topology, create a separate branch for each task, and
open a pull request. Avoid concurrent changes to the same file. Do not commit
tokens, .env, generated artifacts or invented measurements. Collaborator invitations
remain with the repository owner; no friends were invited or messaged automatically.

## Mentor demonstration order

1. Explain the hospital groups, hosts, switches and links using the dashboard.
2. Say explicitly whether the view is simulation or the local real lab.
3. Show the existing C1 restriction report: ordinary ping blocked while measured
   monitor probes were preserved; use the report's exact measured phase counts.
4. Show live controller telemetry and, when the new runtime is actually running,
   real scores and the request → pending → readback-confirmed action distinction.
5. Show the Human Override panel (section 05 on the Overview tab): demonstrate
   that it is greyed out in simulation mode and becomes active only in live mode;
   explain that a 32+ character action token is required, ack must be checked, and
   that the panel posts to `/v1/actions` via the loopback bridge — queued ≠ confirmed.
6. Show recovery and retain logs. Until the new OVS gate is run, present automatic
   enforcement integration as implemented and locally tested, not validated on the
   laptop. The action policy is threshold detection; optional M1/M2 snapshot scores
   are observational until trained on controlled data and explicitly reviewed.

The remaining physical gate is a controlled Mint run with the new image and runtime.
It must verify C1–C5 delivery and noncritical blocking during actions, timed recovery,
restart behavior, actual latency, and load effects. These cannot be measured by a
hosted animation or a fake-switch test.

For one combined portable check, run `python3 scripts/check.py` from the repo root.
The latest successful combined run contains **141 Python tests**, plus Node UI logic checks.
The C1–C5 worker suite and finite runner are now implemented; see DEMO.md. Their
actual Ryu/OVS execution remains a separate pending gate.

The Windows-friendly results exporter and remaining-work table are in EVALUATION.md.
