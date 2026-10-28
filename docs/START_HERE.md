# Start MedSeg with your team

## Open the published website — no installation

**https://medseg-hospital-console.shadyowl16.chatgpt.site**

The browser demonstration is public: anyone with this link can open it on Windows,
Linux, macOS or a phone. Choose an Attack source and click Run containment demo.
Watch the destination/port counts, held containment and continuing clinical paths.
Choose Review device evidence to record your assessment. Browser controls do not
scan a computer or change a real hospital network. The public site cannot connect
to Pranit's laptop. Guided traffic is clearly labelled simulation.

## Get the source files

The current project is on **feature/hospital-topology**, not necessarily main:

https://github.com/rishabhjaincares-droid/SDN-Microsegmentation/tree/feature/hospital-topology

The GitHub repository's permissions are unchanged. For a private repository, the
owner must add teammates as collaborators and each teammate must accept access.
If cloning asks for authentication, use `gh auth login` and `gh auth setup-git`,
or use GitHub Desktop. A GitHub account password is not a Git HTTPS credential.

```bash
git clone --branch feature/hospital-topology --single-branch https://github.com/rishabhjaincares-droid/SDN-Microsegmentation.git
cd SDN-Microsegmentation
```

Alternatively, use GitHub's Code → Download ZIP on that branch and extract it.

## Run the website locally — Python 3, no npm or Linux needed

From the extracted/cloned project folder, on Windows:

```powershell
py -3 start_dashboard.py
```

On Linux/macOS:

```bash
python3 start_dashboard.py
```

The launcher opens **http://127.0.0.1:8088**. Leave its terminal open; Ctrl+C stops
it. The dashboard uses Python's standard library and does not install anything.
If Python is not installed, use the published website above immediately.
For an occupied port, stop your other dashboard or use `--port=8089`. For a
headless machine use `--no-browser`. This starts the UI, not the emulated network.
Import a real report.json under Verified evidence to display saved lab results;
files stay in the browser. Never describe simulated counters as measured results.

## Run the real emulated network — configured Linux lab only

First complete the environment steps in [infra/README.md](../infra/README.md).
Mininet/Open vSwitch, PyYAML, Docker and the compatible base image are required.
Windows friends can run the website without these. On Pranit's already configured
Mint laptop, stop a separately running dashboard so port 8088 is available, then:

```bash
sudo systemctl start docker
sudo docker build -t hospital-controller:lab -f controller/Dockerfile .
sudo /usr/bin/python3 scripts/demo.py --enforce --host=random
```

Use `--host=billing1` for a specific office source, or `--host=monitor2` for a
medical-device restriction case. Critical servers are review-only in this
runner; they are not automatically isolated. Open http://127.0.0.1:8088 during
the finite run and choose Connect your lab → Read local controller. The runner
stops its own services automatically and saves artifacts/demo/RUN_ID/report.json.
A timed rule's expiry does not disinfect a host. Real rules remain bounded even
though the teaching simulation waits for user review.

See [DEMO.md](DEMO.md) for evidence requirements and limitations. The earlier
reception1 run was student-reported PASS; other source/action cases need real
validation. We do not ship invented successful experiment reports.

## Contribute without Linux

Clone the branch above, then create a separate task branch:

```bash
git switch -c feature/your-task-name
```

Windows teammates can edit the dashboard, improve tests/docs, analyse supplied
results and prepare the presentation. For Python tests, use Python 3.12 and install
`PyYAML==6.0.2` into a virtual environment. Run `python scripts/check.py` (Windows:
`py -3 scripts/check.py`). Node enables the additional UI logic checks. These
checks do not need Mininet/root, but some process tests can vary by platform;
record the OS and output instead of assuming a Windows pass from Linux results.
Push your task branch and open a pull request targeting feature/hospital-topology.
Do not commit .env files, tokens, generated artifacts or real patient information.
