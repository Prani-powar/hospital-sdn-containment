"""Read-only checks. Exit nonzero when the host cannot run network smoke tests."""
import json
import os
import shutil
import subprocess
import time


def main() -> int:
    """Emit JSON checks without changing the host."""
    failures = 0
    for command in ["docker", "ovs-vsctl", "ovs-ofctl", "ip"]:
        ok = shutil.which(command) is not None
        failures += not ok
        print(json.dumps({"check": command, "ok": ok, "timestamp_ns": time.monotonic_ns()}))
    for command in [
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        ["ovs-vsctl", "--timeout=5", "show"],
        ["/usr/bin/python3", "-c", "import mininet.net"],
    ]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            ok = result.returncode == 0
            detail = (result.stdout + result.stderr)[-2000:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            ok, detail = False, str(exc)
        failures += not ok
        print(json.dumps({"check": command, "ok": ok, "detail": detail,
                          "timestamp_ns": time.monotonic_ns()}))
    if os.geteuid() != 0:
        print(json.dumps({"check": "root", "ok": False, "detail": "Run preflight with sudo"}))
        failures += 1
    return int(failures > 0)


if __name__ == "__main__":
    raise SystemExit(main())
