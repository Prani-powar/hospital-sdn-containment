# Verified progress — 2026-10-26

Evidence is terminal output/screenshots supplied by the student, not an
independently rerun benchmark.

## Student laptop

- Linux Mint 22.2 Zara, Ubuntu noble base; system Python 3.12.3.
- Mininet, OVS and YAML imports passed. Docker client/server 29.1.3 responded.
- Python 3.9.23 ran in Docker. Bullseye apt downloads returned 404; switching
  to Bookworm allowed the Ryu build to complete.
- Ryu 4.34, eventlet 0.30.2 and the supplied dependency versions installed.
  pip check and app_manager/WSGI/simple_switch_13 imports passed.
- ryu-manager reported 4.34; simple_switch_13 started.
- Two Mininet hosts with OpenFlow 1.3 and remote Ryu reached 0% ping loss.
- Priority-40000 IPv4 source drop with hard_timeout=30 blocked ping; ping
  recovered after expiry and the rule disappeared from dump-flows.
- Python HTTP server on h2:8080 returned 200. Priority-50000 TCP allow rules
  preserved HTTP 200 during a priority-40000 source drop (hard_timeout=60),
  while ping showed 100% loss.
- Temporary Mininet network shut down cleanly.

These demonstrate manual rule mechanics. A source-only IPv4 drop is not complete
bidirectional isolation. One preserved synthetic service does not prove all
hospital safety invariants. Automatic detection is not implemented.

The locally built image was hospital-ryu:lab. Repository container definitions
include extra runtime checks and must be freshly built to verify that exact
version. Compose uses its own image names.

## Authoring checks

Six unittest configuration tests, Python compilation and Bash syntax passed.
Docker/OVS are unavailable in the authoring workspace. The complete automated
smoke.py test, services image build, meter capabilities, controller-disconnection
checks and full hospital experiments remain unverified on the student laptop.
