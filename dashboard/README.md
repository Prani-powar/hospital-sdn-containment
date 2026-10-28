# MedSeg mentor console

A buildless interactive dashboard for the hospital SDN project. Open the [public website](https://medseg-hospital-console.shadyowl16.chatgpt.site)
to present the guided simulation, or run the UI on Windows/Linux/macOS with
`python start_dashboard.py` from the repository root. See [Start here](../docs/START_HERE.md).
You can also run the existing server directly on Mint:

```bash
cd ~/SDN-Microsegmentation
/usr/bin/python3 dashboard/serve.py
```

Open **http://127.0.0.1:8088** in that laptop's browser. No npm installation or new
Python dependency is required. Fonts fall back to system fonts without internet.

## What to demonstrate

1. Select any of the 24 configured hosts. Explain its role and response policy.
2. Click **Run containment demo**. Pause, resume, change speed, or reset.
3. Select a monitor or clinical workstation, choose **Use as demo source**, then
   run again: it is RESTRICTed, never fully isolated. Critical servers require attributed-source protection and review; the UI does not isolate them.
4. Open **Clinical policies**: inspect the five synthetic service groups and distinguish supplied results from current live measurements.
5. Open **Verified evidence**: recorded 552/552 connectivity, 393/393 C1 replies,
   and the timed before/restricted/recovered results. These are user-supplied
   terminal results, not live readings.
6. Optionally import a restriction-report.json. Parsing is local, size-limited,
   and validates the three phases and probe counts; no file is uploaded. Imported
   results are labelled user-provided, not independently verified.

## Live telemetry

Leave the actual custom controller and Mininet running. In the locally served
version, choose **Connect your lab → Read local controller**. The Python bridge
reads only GET /v1/health and GET /v1/stats on 127.0.0.1:18080. It binds loopback,
checks Host/Origin, follows no user-supplied destination, and exposes no action API.
The hosted version cannot reach your laptop and explains how to start this server.

Live charts show source-ingress IPv4 forwarding-rule hit deltas, not application
delivery. They exclude PacketOut first packets and newly seen counter baselines.
Incomplete counters are visibly labelled. This overview is not the feature
extractor: it does not claim exact rate accounting through rule churn or restart.
Live health and statistics are separate acquisitions. Fresh detector features/scores and clinical probes are displayed when their local
processes provide matching snapshots. Network controls remain read-only; missing
evidence stays unavailable rather than inventing healthy values.

## Design and scope

Requirement: provide a mentor-facing visual walkthrough immediately. Assumptions:
static 24-host topology, existing loopback controller, user-verified evidence.
Risks: confusing simulations with measurements or suggesting UI controls enforce
network policy. Decision: simulation by default with persistent labels, separate
recorded-evidence view, and opt-in local read-only telemetry. No new rule writes,
model claims, or safety-invariant changes are introduced. A Python bridge avoids
changing the controller's CORS/authentication settings.

Validation: JavaScript syntax, browser interactions for navigation, host selection,
scenario progression, pause/reset, evidence and connection guidance; Python syntax
and local HTTP bridge error behavior. Browser QA and deployment status are reported
in the delivery message. The mentor demo is not proof of automatic threat detection.

Self-review: role-aware actions are illustrative only, medical/clinical roles are
never labelled ISOLATE, and critical-server PROTECT is not implemented by a button.
The static topology and embedded reference evidence are maintained explicitly;
they are not advertised as auto-discovered live state. No cloud service can access
the laptop through this UI. The local server is for a single-user lab demonstration.

## Live decision status

The local bridge now imports fresh `artifacts/decision-status.json` from
`python3 -m decision.live`. Observe mode displays real detector output without
writing rules. Explicitly enabled enforcement shows pending/failed/confirmed
action status. ACK labels refer to historical rule readback, not continuous
verification or clinical delivery. Stale, stopped or wrong-epoch status is rejected.
The hosted dashboard remains simulation-only. See `decision/LIVE.md`.

## Five-service evidence and finite demo reports

The local bridge also reads fresh matching-epoch critical-status.json from the
finite runner. A clinical PASS requires replies from all 13 configured sources;
missing/stale data stays unmeasured. The evidence importer supports both the old
C1 restriction report and the new finite-demo report. See ../docs/DEMO.md.
`node dashboard/test_live_ui.js` checks actual UI state/report logic without
claiming a rendered browser or actual OVS test.

The live chart draws gaps after incomplete polls, restarts, rule-set changes or
counter resets. Such intervals are not displayed as zero traffic.
