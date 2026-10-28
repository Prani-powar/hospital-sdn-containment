"""Real Ryu parser/adapter checks run during the Python 3.9 image build."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from ryu.lib.packet import arp, ethernet, ipv4, packet, udp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from webob import Request

from controller.app import HospitalController, TelemetryAPI
from controller.action_api import ActionAPI, RyuAdapter
from controller.enforcement import Compiler, load_enforcement
from decision.detection import DetectionPolicy, load_detection_config
from pathlib import Path


class Datapath:
    """Serialize real OF1.3 messages without claiming to be an Open vSwitch."""
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self, dpid: int) -> None:
        self.id, self.xid = dpid, 0
        self.messages = []

    def set_xid(self, message: object) -> None:
        self.xid += 1
        message.set_xid(self.xid)

    def send_msg(self, message: object) -> bool:
        if message.xid is None:
            self.set_xid(message)
        message.serialize()
        self.messages.append(message)
        return True


class RyuAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wsgi = SimpleNamespace(register=lambda *args: None)
        with patch("controller.app.hub.spawn", return_value=None):
            self.app = HospitalController(wsgi=self.wsgi)

    def attach(self, dpid: int) -> Datapath:
        dp = Datapath(dpid)
        self.app.features(SimpleNamespace(msg=SimpleNamespace(datapath=dp)))
        return dp

    def test_real_parser_for_udp_match_flowmod_and_packetout(self) -> None:
        dp = self.attach(0x14)
        src, dst = self.app.fabric.hosts["monitor1"], self.app.fabric.hosts["central_mon"]
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst=dst["mac"], src=src["mac"], ethertype=0x0800))
        p.add_protocol(ipv4.ipv4(src=src["address"], dst=dst["address"], proto=17))
        p.add_protocol(udp.udp(src_port=25000, dst_port=18001))
        p.add_protocol(b"synthetic")
        p.serialize()
        msg = SimpleNamespace(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                              data=bytes(p.data), total_len=len(p.data), match={"in_port": 2})
        self.app.packet_in(SimpleNamespace(msg=msg))
        normal = [m for m in dp.messages if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)
                  and m.priority == 10000]
        self.assertEqual(len(normal), 1)
        self.assertEqual(normal[0].match["udp_dst"], 18001)
        self.assertEqual(normal[0].instructions[0].actions[0].port, 1)
        self.assertTrue(any(isinstance(m, ofproto_v1_3_parser.OFPPacketOut) for m in dp.messages))
        self.assertEqual(self.app.observations[0]["host"], "monitor1")
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertEqual(len(self.app.rule_budget.leases[dp.id]), 1)
        self.app.mod_bucket.tokens = 0
        self.app.mod_bucket.rate = 0
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertEqual(self.app.counts["normal_flow_mod_rate_limited"], 1)
        self.assertEqual(self.app.counts["normal_rule_capacity_exhausted"], 0)
        self.app.mod_bucket.tokens = 1
        self.app.rule_budget.limit = 1
        p.protocols[2].dst_port = 18002
        p.serialize()
        msg.data, msg.total_len = bytes(p.data), len(p.data)
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertEqual(self.app.counts["normal_rule_capacity_exhausted"], 1)
        self.assertEqual(self.app.counts["normal_install_budget_exhausted"], 2)
        # Wrong attachment must not add any flow or packet-out.
        before = len(dp.messages)
        msg.match["in_port"] = 3
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertEqual(len(dp.messages), before)

    def test_real_wsgi_response_and_stats_request_serialization(self) -> None:
        api = TelemetryAPI(Request.blank("/v1/health"), None, {"app": self.app})
        self.assertEqual(api.health(None).status_int, 503)
        for dpid in self.app.fabric.switches:
            dp = self.attach(dpid)
            if dpid in self.app.polled:
                request = dp.ofproto_parser.OFPFlowStatsRequest(dp, table_id=0)
                dp.set_xid(request)
                self.assertTrue(self.app.send(dp, request))
                self.app.cache.begin(dpid, request.xid, time.monotonic_ns())
                self.app.stats_reply(SimpleNamespace(msg=SimpleNamespace(
                    datapath=dp, xid=request.xid, body=[], flags=0)))
        response = api.health(None)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(json.loads(response.body)["status"], "ok")
        self.assertTrue(json.loads(api.stats(None).body)["complete"])
        self.assertEqual(json.loads(api.topology(None).body)["topology"]["name"], "hospital")

    def test_real_arp_serialization_without_flooding(self) -> None:
        dp = self.attach(0x14)
        src, dst = self.app.fabric.hosts["monitor1"], self.app.fabric.hosts["central_mon"]
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src["mac"], ethertype=0x0806))
        p.add_protocol(arp.arp(opcode=1, src_mac=src["mac"], src_ip=src["address"],
                               dst_mac="00:00:00:00:00:00", dst_ip=dst["address"]))
        p.serialize()
        self.app.packet_in(SimpleNamespace(msg=SimpleNamespace(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER, data=bytes(p.data),
            total_len=len(p.data), match={"in_port": 2})))
        normal = [m for m in dp.messages if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)
                  and m.priority == 10000]
        self.assertEqual(len(normal), 1)
        self.assertEqual(normal[0].match["arp_tpa"], dst["address"])
        self.assertEqual(normal[0].instructions[0].actions[0].port, 1)

    def test_real_action_flowmods_strict_deletes_and_filtered_requests(self) -> None:
        root = Path(__file__).resolve().parents[1]
        policy = load_detection_config(root/'configs/detection.yaml', self.app.fabric)
        compiler = Compiler(self.app.fabric, load_enforcement(root/'configs/enforcement.yaml', self.app.fabric), policy)
        planner = DetectionPolicy(self.app.fabric, policy)
        planner.epoch = self.app.epoch
        proposal = planner._proposal('monitor1', 'RESTRICT', time.monotonic_ns(), 'adapter test')
        _, rules = compiler.compile(proposal, self.app.epoch)
        for dpid in self.app.fabric.switches:
            self.attach(dpid)
        adapter = RyuAdapter(self.app)
        for rule in compiler.floor + rules:
            prepared = adapter.prepare('add', rule.dpid, rule=rule)
            prepared.message.serialize()
            self.assertEqual(prepared.message.priority, rule.priority)
        for rule in rules:
            prepared = adapter.prepare('delete', rule.dpid, rule=rule)
            prepared.message.serialize()
            self.assertEqual(prepared.message.command, ofproto_v1_3.OFPFC_DELETE_STRICT)
            self.assertEqual(prepared.message.cookie_mask, 0xffffffffffffffff)
        with self.assertRaises(ValueError):
            adapter.prepare('delete', compiler.floor[0].dpid, rule=compiler.floor[0])
        for kind, params in [('stats', {'cookie': compiler.namespace('monitor1'), 'mask': 0xffffff0000000000}), ('barrier', {})]:
            adapter.prepare(kind, 0x14, **params).message.serialize()

    def test_action_http_gate_disabled_auth_and_body_limit(self) -> None:
        request = Request.blank('/v1/actions', method='POST', body=b'{}')
        api = ActionAPI(request, None, {'app': self.app})
        self.assertEqual(api.submit(request).status_int, 503)
        with patch.dict(os.environ, {'HOSPITAL_ENABLE_ACTIONS':'1', 'HOSPITAL_ACTION_TOKEN':'x'*32}):
            with patch('controller.app.hub.spawn', return_value=None):
                enabled = HospitalController(wsgi=self.wsgi)
        api = ActionAPI(request, None, {'app': enabled})
        self.assertEqual(api.submit(request).status_int, 401)
        request.headers['Authorization'] = 'Bearer ' + 'x'*32
        request.body = b'x'*16385
        self.assertEqual(api.submit(request).status_int, 413)
        request.body = b'{}'
        enabled.health = lambda: {'status':'ok'}
        self.assertEqual(api.submit(request).status_int, 400)

    def test_global_circuit_opens_without_parsing_more_packet_payload(self) -> None:
        dp = self.attach(0x14)
        self.app.global_bucket.tokens = 0
        msg = SimpleNamespace(datapath=dp)
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertGreater(self.app.global_guard_until, time.monotonic())
        self.app.packet_in(SimpleNamespace(msg=msg))
        self.assertEqual(self.app.counts["global_guard_drops"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
