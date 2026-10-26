"""Isolated two-host OVS smoke test; not the project's containment controller."""
import argparse
import json
import os
import signal
import socket
import subprocess
import time
import uuid
from pathlib import Path


def validate(config: dict) -> None:
    """Reject configuration that exposes the controller or weakens smoke assertions."""
    if config["controller_host"] != "127.0.0.1":
        raise ValueError("Smoke controller must be VM-local")
    for field in ["controller_port", "critical_port"]:
        if type(config[field]) is not int or not 1024 <= config[field] <= 65535:
            raise ValueError(f"Invalid {field}")
    if config["critical_priority"] != 50000 or config["quarantine_priority"] != 40000:
        raise ValueError("Project priority contract must not change")
    for field in ["connect_timeout_s", "quarantine_timeout_s"]:
        if type(config[field]) is not int or not 1 <= config[field] <= 30:
            raise ValueError(f"Invalid {field}")


def run_command(args: list[str]) -> str:
    """Execute bounded commands without shell expansion."""
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=10).stdout


def emit(check: str, **details: object) -> None:
    """Write infrastructure observations, separate from experiment Event contracts."""
    print(json.dumps({"check": check, "timestamp_ns": time.monotonic_ns(),
                      **details}), flush=True)


def main(config: dict) -> None:
    """Verify connectivity, critical-rule precedence, quarantine expiry and meters."""
    validate(config)
    if os.geteuid() != 0:
        raise RuntimeError("Run sudo /usr/bin/python3 infra/smoke.py")
    # Import after validation so unit tests do not require Mininet.
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController

    with socket.create_connection((config["controller_host"], config["controller_port"]), 3):
        pass
    token = uuid.uuid4().hex[:6]
    bridge = "hs" + token
    # Unique names and no mn -c: never delete unrelated lab bridges.
    net = Mininet(controller=None, switch=OVSSwitch, build=False)
    server = None
    try:
        controller = net.addController("c" + token, controller=RemoteController,
                                       ip=config["controller_host"],
                                       port=config["controller_port"])
        switch = net.addSwitch(bridge, protocols="OpenFlow13", failMode="secure")
        h1 = net.addHost("a" + token, ip="10.254.250.1/24")
        h2 = net.addHost("b" + token, ip="10.254.250.2/24")
        net.addLink(h1, switch)
        net.addLink(h2, switch)
        net.build()
        controller.start()
        switch.start([controller])
        if not net.waitConnected(timeout=config["connect_timeout_s"]):
            raise RuntimeError("OpenFlow connection did not become ready")
        # Avoid ARP as a confounder for this isolated IPv4 rule test.
        h1.setARP(h2.IP(), h2.MAC())
        h2.setARP(h1.IP(), h1.MAC())

        def ofctl(*args: str) -> str:
            return run_command(["ovs-ofctl", "-O", "OpenFlow13", *args])

        def ping_ok() -> bool:
            return h1.pexec(["ping", "-c", "1", "-W", "1", h2.IP()])[2] == 0

        if not ping_ok():
            raise AssertionError("Baseline forwarding failed")
        emit("baseline_forwarding", status="PASS")
        port = config["critical_port"]
        server_code = (
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            f"s.bind(('0.0.0.0',{port}));"
            "\nwhile True:\n d,a=s.recvfrom(2048); s.sendto(d,a)"
        )
        server = h2.popen(["/usr/bin/python3", "-u", "-c", server_code],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client_code = (
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            "s.settimeout(1);"
            f"s.sendto(b'probe',('{h2.IP()}',{port}));"
            "assert s.recv(2048)==b'probe'"
        )

        def probe_ok() -> bool:
            return h1.pexec(["/usr/bin/python3", "-c", client_code])[2] == 0

        deadline = time.monotonic() + 5
        while not probe_ok():
            if server.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError("UDP echo baseline failed")
            time.sleep(0.1)
        # Synthetic critical UDP service, explicit output ports, both directions.
        out1 = switch.ports[switch.connectionsTo(h1)[0][0]]
        out2 = switch.ports[switch.connectionsTo(h2)[0][0]]
        for src, dst, field, out in [
            (h1.IP(), h2.IP(), f"tp_dst={port}", out2),
            (h2.IP(), h1.IP(), f"tp_src={port}", out1),
        ]:
            ofctl("add-flow", bridge,
                  f"cookie=0x50000,priority=50000,udp,nw_src={src},nw_dst={dst},"
                  f"{field},actions=output:{out}")
        ttl = config["quarantine_timeout_s"]
        ofctl("add-flow", bridge,
              f"cookie=0x40000,priority=40000,ip,nw_src={h1.IP()},"
              f"hard_timeout={ttl},actions=drop")
        ofctl("barrier", bridge)
        if ping_ok():
            raise AssertionError("Quarantine did not block non-critical ICMP")
        if not probe_ok():
            raise AssertionError("Higher priority critical UDP rule was overridden")
        emit("critical_allow_over_drop", status="PASS")
        # Controller loss: permanent allow remains and hard timeout still expires.
        run_command(["ovs-vsctl", "del-controller", bridge])
        if not probe_ok():
            raise AssertionError("Critical UDP failed after controller disconnect")
        time.sleep(ttl + 1)
        flows = ofctl("dump-flows", bridge)
        if "cookie=0x40000" in flows:
            raise AssertionError("Quarantine hard timeout did not expire")
        if "cookie=0x50000" not in flows or not probe_ok():
            raise AssertionError("Critical allow disappeared")
        emit("disconnect_and_expiry", status="PASS")
        # Capability probe only: not proof of accurate rate enforcement.
        try:
            features = ofctl("meter-features", bridge)
            ofctl("add-meter", bridge, "meter=1,pktps,band=type=drop,rate=100")
            emit("meter_installation", status="PASS", details=features)
        except subprocess.CalledProcessError as exc:
            emit("meter_installation", status="UNSUPPORTED", details=exc.stderr,
                 fallback="allow-list restriction only")
        finally:
            # Scoped to our bridge; unsupported deletion is non-fatal.
            subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "del-meters", bridge],
                           capture_output=True, timeout=10)
        emit("network_smoke", status="PASS")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=3)
        net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        default=Path(__file__).with_name("smoke_config.json"))
    args = parser.parse_args()

    def interrupted(signum: int, frame: object) -> None:
        """Allow the cleanup block to run on termination."""
        raise KeyboardInterrupt(f"Received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(json.loads(args.config.read_text()))
    except Exception as exc:
        emit("network_smoke", status="FAIL", error=str(exc))
        raise SystemExit(1)
