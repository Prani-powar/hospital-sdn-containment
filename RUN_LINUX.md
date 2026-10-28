# Run this version on Linux Mint

Extract this ZIP into a new folder. Open a terminal in that extracted folder.

For the website simulation only:

```bash
python3 start_dashboard.py
```

For the real persistent Mininet lab (already configured Mint laptop):

1. Exit previous Mininet labs and stop your previous controller/dashboard processes.
2. Run:

```bash
sudo systemctl start docker
sudo docker build -t hospital-controller:lab -f controller/Dockerfile .
sudo /usr/bin/python3 scripts/lab.py
```

3. Keep that terminal running. Open http://127.0.0.1:8088.
4. In REAL LOCAL LAB SESSION wait for ready, select an eligible endpoint and
   click Start harmless probe. If needed select Connect your lab → Read local controller.
5. Wait for confirmed release and ready before another scenario. Ctrl+C stops the session.

Includes the optional-ML import fix and the null confirmation-time crash fix.
The dark/orange dashboard and sequential simulation animation are preserved.
ML tooling is included, but model scores require separately trained local artifacts.
No action token, patient data, model artifacts or run reports are bundled.

The persistent lab is still undergoing real Mint/OVS validation. A successful
finite billing1 experiment is separate evidence, not proof of repeated sessions.
If startup fails, retain the launcher error and its printed owned log path.
See docs/PERSISTENT_LAB.md for limitations and diagnostics.
