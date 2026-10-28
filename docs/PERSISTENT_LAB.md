# Persistent mentor lab (local implementation; OVS validation pending)

After building the current controller image on the configured Linux Mint laptop:

```bash
cd ~/SDN-Microsegmentation
sudo /usr/bin/python3 scripts/lab.py
```

Open http://127.0.0.1:8088. The **Real local lab session** panel appears only when
this launcher is running. Wait for **ready**, choose an eligible endpoint and
press **Start harmless probe**. This switches to live view and launches actual
bounded Mininet traffic at four packets/second for 16 seconds. The existing
threshold detector chooses a role action; its controller confirmation appears in
the session timeline. An accepted command is only queued, not successful isolation.

The session stays open until Ctrl+C in the launcher terminal. The automatic
containment remains timed. Source flags remain for human assessment after release.
The next scenario is enabled after confirmed release, the probe exits successfully,
and a cooldown clears overlapping detection windows. No controller or planner
restart is used between scenarios. Clinical workers renew between scenarios;
the brief renewal interval is reported, not presented as continuous delivery.

The map moves an affected endpoint only after the confirmed action's exact cookie
namespace/version has IPv4 drop rules read back from every switch. This is a
recent rule observation, not proof of malware removal or all-protocol isolation.
Fresh clinical replies alone animate clinical paths. Missing data stays unmeasured.
The existing evidence review and advanced teammate override panel are preserved.
The advanced panel's independent manual-action workflow is not validated by this
launcher and is not required to run scenarios; its proposal compatibility remains
separate work. The controller token stays in the launcher/controller/decision
process environment and is not sent to the browser.

## Troubleshooting

Port errors name the port: use `sudo ss -ltnp` to identify its owner. Exit only your
previous lab process. Missing image errors provide the exact build command.
Docker and OVS errors identify the unavailable service. Existing topology bridges
and interfaces are refused by the topology loader; inspect them before cleanup.
Do not use blanket `mn -c` or kill commands while other labs are active.

The launcher uses sudo and writes owned run logs under `artifacts/demo/RUN_ID`.
It monitors owned controller, detector and clinical workers, and stops on their
failure. A controller epoch change refuses further scenarios. Cleanup uses the
owned container ID, owned subprocess handles and the topology's own teardown.
Old finite reports are preserved. No new finite PASS report is fabricated for a
persistent session. Read the launcher error and its log directory before retrying.

## Required laptop checks

The authoring environment cannot execute Mininet/Docker/OVS. On Mint verify: idle
session remains open beyond three minutes; clinical renewals recover fresh data;
billing1 followed by guest1 completes confirmed containment/release; medical role
restriction preserves required services; Ctrl+C releases owned resources; an
occupied port is reported without touching its owner. Keep the existing finite
billing1 PASS as separate evidence; it does not validate this new session mode.
