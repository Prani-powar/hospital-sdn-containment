"""Validated config-driven Mininet hospital. No containment policy is installed."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
from typing import Any

import yaml

LOGGER = logging.getLogger("hospital.topology")
ROLES = frozenset({"admin", "clinical", "critical_server", "iomt", "guest", "vendor"})
DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "hospital.yaml"


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject ambiguous mappings while retaining safe YAML constructors."""


def unique_mapping(loader: UniqueKeyLoader, node: Any) -> dict:
    """Construct a mapping and fail on repeated keys."""
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"Duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def emit(check: str, **details: Any) -> None:
    """Log infrastructure observations without changing the experiment Event contract."""
    LOGGER.info(json.dumps({"check": check, "timestamp_ns": time.monotonic_ns(), **details}))


def require(condition: bool, message: str) -> None:
    """Raise an actionable validation error instead of relying on assert."""
    if not condition:
        raise ValueError(message)


def plan(config: dict[str, Any]) -> dict[str, Any]:
    """Validate the lab configuration and generate deterministic nodes and links."""
    require(isinstance(config, dict), "Configuration must be a mapping")
    require(config.get("schema_version") == 1, "Unsupported configuration schema")
    network = ipaddress.IPv4Network(config["subnet"], strict=True)
    private_ranges = [ipaddress.IPv4Network(n) for n in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    require(any(network.subnet_of(n) for n in private_ranges),
            "Use an RFC1918 private lab subnet")
    controller = config["controller"]
    require(controller["host"] == "127.0.0.1", "Controller must be local to the lab")
    require(type(controller["port"]) is int and 1024 <= controller["port"] <= 65535,
            "Controller port must be an integer between 1024 and 65535")
    require(type(controller["connect_timeout_s"]) is int
            and 1 <= controller["connect_timeout_s"] <= 60,
            "Controller connection timeout must be 1..60 seconds")
    names: set[str] = set()
    dpids: set[str] = set()
    addresses: set[str] = set()

    def register_name(name: str) -> None:
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,13}", name)
                is not None, f"Invalid or too-long node name: {name}")
        require(name not in names, f"Duplicate node name: {name}")
        names.add(name)

    def switch(name: str, dpid: str) -> dict:
        register_name(name)
        # Default switch interface names must fit Linux's 15-character limit.
        require(len(name) <= 8, f"Switch name too long for generated interfaces: {name}")
        require(isinstance(dpid, str) and re.fullmatch(r"[0-9a-fA-F]{16}", dpid)
                is not None and int(dpid, 16) != 0, "DPID must be 16 nonzero hex digits")
        require(dpid.lower() not in dpids, f"Duplicate DPID: {dpid}")
        dpids.add(dpid.lower())
        return {"name": name, "dpid": dpid.lower()}

    register_name(controller["name"])
    switches = [switch(config["core"]["name"], config["core"]["dpid"])]
    hosts: list[dict] = []
    links: list[dict] = []
    segments = config["segments"]
    require(isinstance(segments, list) and 1 <= len(segments) <= 16,
            "Expected 1..16 access segments")
    segment_names: set[str] = set()
    for index, segment in enumerate(segments, start=1):
        require(isinstance(segment["name"], str) and segment["name"]
                and segment["name"] not in segment_names, "Duplicate or empty segment name")
        segment_names.add(segment["name"])
        access = switch(segment["switch"], segment["dpid"])
        switches.append(access)
        links.append({"node1": switches[0]["name"], "node2": access["name"],
                      "port1": index, "port2": 1})
        require(isinstance(segment["hosts"], list) and segment["hosts"],
                "Every segment needs hosts")
        require(len(segment["hosts"]) <= 128, "Too many hosts in one segment")
        for port, host in enumerate(segment["hosts"], start=2):
            register_name(host["name"])
            require(host["role"] in ROLES, f"Unknown role: {host['role']}")
            address = ipaddress.IPv4Interface(host["ip"])
            require(address.network == network and address.ip not in
                    (network.network_address, network.broadcast_address),
                    f"Host address outside usable lab subnet: {host['ip']}")
            require(str(address.ip) not in addresses, f"Duplicate IP: {address.ip}")
            addresses.add(str(address.ip))
            number = len(hosts) + 1
            require(number <= 256, "Maximum 256 emulated hosts")
            # Host label central_mon is too long for central_mon-eth0.
            interface = f"h{number:03d}-eth0"
            mac = "02:00:00:00:" + f"{number // 256:02x}:{number % 256:02x}"
            hosts.append({"name": host["name"], "ip": str(address), "role": host["role"],
                          "segment": segment["name"], "switch": access["name"],
                          "switch_port": port, "mac": mac, "interface": interface})
            links.append({"node1": host["name"], "node2": access["name"],
                          "port1": 0, "port2": port, "intfName1": interface})
    expected = config["expected_host_count"]
    require(type(expected) is int and len(hosts) == expected,
            f"Expected {expected} hosts, found {len(hosts)}")
    return {"name": config["name"], "subnet": str(network), "controller": dict(controller),
            "switches": switches, "hosts": hosts, "links": links}


def load_plan(path: Path) -> dict[str, Any]:
    """Read a bounded configuration file without executing YAML objects."""
    require(path.stat().st_size <= 1_000_000, "Configuration exceeds 1 MB")
    return plan(yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader))


def populate(net: Any, topology: dict, switch_class: Any, controller_class: Any) -> None:
    """Add only configured virtual nodes and links to an unbuilt Mininet instance."""
    c = topology["controller"]
    net.addController(c["name"], controller=controller_class, ip=c["host"], port=c["port"])
    for s in topology["switches"]:
        net.addSwitch(s["name"], cls=switch_class, dpid=s["dpid"],
                      protocols="OpenFlow13", failMode="secure")
    for h in topology["hosts"]:
        net.addHost(h["name"], ip=h["ip"], mac=h["mac"])
    for link in topology["links"]:
        params = dict(link)
        node1, node2 = params.pop("node1"), params.pop("node2")
        net.addLink(node1, node2, **params)


def planned_interfaces(topology):
    """All explicit link ends, including switch uplinks from crashed sessions."""
    return sorted({link.get('intfName'+str(side), f"{link['node'+str(side)]}-eth{link['port'+str(side)]}")
                   for link in topology['links'] for side in (1,2)})


def run(topology: dict, ping_all: bool, traffic: dict | None = None,
        restriction: dict | None = None, critical_suite: dict | None = None, exercise=None, experiment_run_id: str | None = None) -> None:
    """Launch the isolated network; always stop owned resources on normal errors."""
    require(not critical_suite or not (traffic or restriction or ping_all),
            "Critical suite is separate from the C1/baseline modes")
    require(os.geteuid() == 0, "Live emulation requires sudo /usr/bin/python3")
    result = subprocess.run(["ovs-vsctl", "--timeout=5", "list-br"],
                            capture_output=True, text=True, check=True, timeout=8)
    existing = set(result.stdout.splitlines())
    collisions = existing.intersection(s["name"] for s in topology["switches"])
    require(not collisions, f"Existing lab switches found: {sorted(collisions)}. "
            "Exit the other lab before continuing.")
    # Refuse to adopt interface resources left by another/crashed lab.
    collisions = [name for name in planned_interfaces(topology)
                  if (Path("/sys/class/net") / name).exists()]
    require(not collisions, f"Existing lab interface names: {collisions}. No resources were adopted; inspect these exact interfaces before scoped cleanup.")
    c = topology["controller"]
    with socket.create_connection((c["host"], c["port"]), timeout=3):
        pass
    from mininet.cli import CLI
    from mininet.log import lg, setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController

    setLogLevel("info")
    # Mininet already owns a console handler; avoid replay through our root logger.
    lg.propagate = False
    net = Mininet(controller=None, switch=OVSSwitch, build=False)
    traffic_manager = None
    try:
        populate(net, topology, OVSSwitch, RemoteController)
        net.build()
        net.start()
        require(net.waitConnected(timeout=c["connect_timeout_s"]),
                "Not all six switches connected to the controller")
        emit("topology_ready", hosts=len(net.hosts), switches=len(net.switches),
             links=len(topology["links"]))
        for host in topology["hosts"]:
            emit("host_mapping", **host)
        if traffic:
            try:
                from .clinical import ClinicalTraffic
            except ImportError:
                from clinical import ClinicalTraffic
            traffic_manager = ClinicalTraffic(net, traffic,
                                             DEFAULT_CONFIG.parents[1] / "artifacts" / "clinical")
            traffic_manager.start()
        if critical_suite:
            try:
                from .critical_suite import CriticalSuite
            except ImportError:
                from critical_suite import CriticalSuite
            traffic_manager = CriticalSuite(net, critical_suite,
                DEFAULT_CONFIG.parents[1]/"artifacts"/"critical-suite",run_id=experiment_run_id)
            traffic_manager.start()
            emit("critical_suite_ready", run_id=traffic_manager.run_id,
                 directory=str(traffic_manager.directory))
        if exercise:
            exercise(net, traffic_manager)
        elif restriction:
            try:
                from .restriction_demo import run as run_demo
            except ImportError:
                from restriction_demo import run as run_demo
            run_demo(net, topology, traffic, traffic_manager, restriction)
        elif ping_all:
            loss = net.pingAll(timeout="1")
            emit("baseline_ping", loss_percent=loss)
            require(loss == 0, f"Baseline ping loss was {loss}%; inspect controller output")
        else:
            CLI(net)
    finally:
        try:
            if traffic_manager:
                traffic_manager.stop()
        finally:
            net.stop()
            emit("topology_stopped")


def main() -> int:
    """Support unprivileged plan validation and privileged interactive emulation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--validate-only", action="store_true",
                        help="Print the topology plan without importing Mininet")
    parser.add_argument("--ping-all", action="store_true",
                        help="Run baseline all-pairs ping then exit; no containment")
    parser.add_argument("--traffic", type=Path,
                        help="Start finite synthetic C1 probes from this YAML configuration")
    parser.add_argument("--restrict-demo", type=Path,
                        help="Run the finite C1 rule test and exit, using this YAML configuration")
    parser.add_argument("--critical-suite", type=Path,
                        help="Run all five synthetic clinical services; separate from --traffic")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    def terminate(signum: int, frame: Any) -> None:
        """Unwind the network cleanup block on SIGTERM."""
        raise KeyboardInterrupt(f"Termination signal {signum}")

    signal.signal(signal.SIGTERM, terminate)
    try:
        topology = load_plan(args.config)
        traffic = None
        if args.traffic:
            try:
                from .clinical import load_config
            except ImportError:
                from clinical import load_config
            traffic = load_config(args.traffic, topology)
        critical_suite = None
        if args.critical_suite:
            require(not args.traffic and not args.restrict_demo and not args.ping_all,
                    "--critical-suite is separate from C1 restriction / baseline modes")
            try:
                from .critical_suite import load_config as load_suite
            except ImportError:
                from critical_suite import load_config as load_suite
            critical_suite = load_suite(args.critical_suite, topology)
        restriction = None
        if args.restrict_demo:
            require(not args.ping_all, "--restrict-demo and --ping-all are separate tests")
            try:
                from .restriction_demo import load_config as load_demo
            except ImportError:
                from restriction_demo import load_config as load_demo
            restriction = load_demo(args.restrict_demo, topology, traffic)
        if args.validate_only:
            print(json.dumps({"topology": topology, "traffic": traffic,
                              "restriction": restriction, "critical_suite": critical_suite}, indent=2)
                  if traffic or critical_suite else json.dumps(topology, indent=2))
        else:
            run(topology, args.ping_all, traffic, restriction, critical_suite)
        return 0
    except KeyboardInterrupt:
        emit("interrupted")
        return 130
    except Exception as exc:
        emit("topology_error", error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
