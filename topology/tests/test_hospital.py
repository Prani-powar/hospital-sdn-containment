"""Topology tests: no root, switches or Mininet installation required."""
import copy
from pathlib import Path
import unittest

import yaml

from topology.hospital import UniqueKeyLoader, load_plan, plan, populate

CONFIG = Path(__file__).resolve().parents[2] / "configs" / "hospital.yaml"


class RecordingNetwork:
    """Record the generated topology without claiming to emulate Mininet."""

    def __init__(self) -> None:
        self.calls = []

    def addController(self, name: str, **params: object) -> None:
        self.calls.append(("controller", name, params))

    def addSwitch(self, name: str, **params: object) -> None:
        self.calls.append(("switch", name, params))

    def addHost(self, name: str, **params: object) -> None:
        self.calls.append(("host", name, params))

    def addLink(self, node1: str, node2: str, **params: object) -> None:
        self.calls.append(("link", (node1, node2), params))


class HospitalTests(unittest.TestCase):
    """Verify the actual hospital specification and reject unsafe configuration."""

    def setUp(self) -> None:
        self.config = yaml.safe_load(CONFIG.read_text())

    def test_hospital_inventory_and_roles(self) -> None:
        p = load_plan(CONFIG)
        self.assertEqual(len(p["hosts"]), 24)
        self.assertEqual(len(p["switches"]), 6)
        self.assertEqual(len(p["links"]), 29)
        self.assertEqual([len(s["hosts"]) for s in self.config["segments"]], [4, 6, 5, 6, 3])
        roles = {h["name"]: h["role"] for h in p["hosts"]}
        self.assertEqual(roles["central_mon"], "critical_server")
        self.assertEqual(roles["monitor1"], "iomt")
        self.assertEqual(roles["vendor_gw"], "vendor")

    def test_generated_network_is_one_connected_tree(self) -> None:
        p = plan(self.config)
        nodes = {x["name"] for x in p["hosts"] + p["switches"]}
        visited = {p["switches"][0]["name"]}
        while True:
            before = len(visited)
            for link in p["links"]:
                if link["node1"] in visited or link["node2"] in visited:
                    visited.update((link["node1"], link["node2"]))
            if len(visited) == before:
                break
        self.assertEqual(visited, nodes)
        self.assertEqual(len(p["links"]), len(nodes) - 1)

    def test_macs_interfaces_and_switch_ports_are_unique(self) -> None:
        p = plan(self.config)
        for field in ("ip", "mac", "interface"):
            values = [h[field] for h in p["hosts"]]
            self.assertEqual(len(set(values)), 24)
        self.assertTrue(all(len(h["interface"]) <= 15 for h in p["hosts"]))
        ports = []
        for link in p["links"]:
            ports.extend([(link["node1"], link["port1"]), (link["node2"], link["port2"])])
        self.assertEqual(len(ports), len(set(ports)))

    def test_reject_duplicate_ip_name_and_dpid(self) -> None:
        for field in ("ip", "name"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.config)
                hs = bad["segments"][0]["hosts"]
                hs[1][field] = hs[0][field]
                with self.assertRaises(ValueError):
                    plan(bad)
        self.config["segments"][1]["dpid"] = self.config["core"]["dpid"]
        with self.assertRaises(ValueError):
            plan(self.config)

    def test_reject_unknown_role(self) -> None:
        self.config["segments"][0]["hosts"][0]["role"] = "unknown"
        with self.assertRaises(ValueError):
            plan(self.config)

    def test_reject_invalid_addresses(self) -> None:
        for address in ("10.20.1.1/24", "10.20.0.0/24", "10.20.0.255/24"):
            with self.subTest(address=address):
                self.config["segments"][0]["hosts"][0]["ip"] = address
                with self.assertRaises(ValueError):
                    plan(self.config)

    def test_reject_nonlocal_controller_and_unbounded_wait(self) -> None:
        for field, value in (("host", "0.0.0.0"), ("port", 0),
                             ("port", True), ("connect_timeout_s", 0)):
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(self.config)
                bad["controller"][field] = value
                with self.assertRaises(ValueError):
                    plan(bad)

    def test_reject_public_network_and_wrong_inventory(self) -> None:
        self.config["subnet"] = "8.8.8.0/24"
        with self.assertRaises(ValueError):
            plan(self.config)
        self.config = yaml.safe_load(CONFIG.read_text())
        self.config["segments"][0]["hosts"].pop()
        with self.assertRaises(ValueError):
            plan(self.config)

    def test_reject_duplicate_yaml_keys(self) -> None:
        with self.assertRaises(ValueError):
            yaml.load("schema_version: 1\nschema_version: 2\n", Loader=UniqueKeyLoader)

    def test_openflow13_secure_switches_and_no_external_nodes(self) -> None:
        p = plan(self.config)
        net = RecordingNetwork()
        populate(net, p, "ovs-switch-class", "remote-controller-class")
        switches = [c for c in net.calls if c[0] == "switch"]
        self.assertEqual(len(switches), 6)
        for _, _, params in switches:
            self.assertEqual(params["protocols"], "OpenFlow13")
            self.assertEqual(params["failMode"], "secure")
        self.assertEqual(len([c for c in net.calls if c[0] == "host"]), 24)
        self.assertEqual(len([c for c in net.calls if c[0] == "link"]), 29)
        self.assertEqual(len([c for c in net.calls if c[0] == "controller"]), 1)


if __name__ == "__main__":
    unittest.main()
