"""Actual planner→actor integration with stateful fake OpenFlow tables, not OVS."""
import asyncio
import copy
from pathlib import Path
import unittest

from controller.core import Fabric
from controller.enforcement import Compiler, Transactions, load_enforcement
from controller.tests.test_enforcement import Switches
from decision.detection import from_config
from decision.live import LivePipeline
from decision.replay_detection import demo_records
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.now = 1.0
        self.fabric = Fabric(load_plan(ROOT/'configs/hospital.yaml'))
        self.engine = from_config(ROOT/'configs/hospital.yaml', ROOT/'configs/detection.yaml')
        self.compiler = Compiler(self.fabric, load_enforcement(ROOT/'configs/enforcement.yaml', self.fabric), self.engine.config)
        self.switch = Switches(self.fabric, lambda: self.now)
        self.actor = Transactions(self.compiler, self.switch, 'integrated', lambda: self.now)
        self.switch.actor = self.actor
        self.settle()
        outer = self

        class Client:
            async def get_actions(self):
                return outer.actor.snapshot()

            async def push_rule(self, proposal):
                return outer.actor.submit(proposal)[1]

            remove_rule = push_rule

        self.pipeline = LivePipeline(self.engine, Client(), True, lambda: int(self.now*1e9))

    def settle(self):
        for _ in range(200):
            self.actor.tick()
            self.switch.drain()
            self.now += .1
            if self.actor.active is None and self.actor.ready:
                return
        self.fail('Coordinator did not settle')

    def feature(self, name):
        row = next(r for r in demo_records(self.engine) if r.get('feature', {}).get('host') == name)
        row = copy.deepcopy(row)
        row['feature']['timestamp_ns'] = int(self.now*1e9)
        return {'status': 'ready', 'features': [row['feature']], 'quality': row['quality']}

    def matched(self, name, dst, port):
        h = self.fabric.hosts[name]
        packet = {'in_port': h['switch_port'], 'eth_type': 2048,
                  'ipv4_src': h['address'], 'ipv4_dst': self.fabric.hosts[dst]['address'],
                  'ip_proto': 17, 'udp_src': 30000, 'udp_dst': port}
        rules = [r for r, _ in self.switch.table.values() if r.dpid == h['access_dpid']
                 and all(packet.get(k) == v for k, v in r.match.items())]
        return max(rules, key=lambda r: r.priority) if rules else None

    def test_live_proposal_pending_confirmed_then_explicit_release(self):
        self.pipeline.ingest(self.feature('reception1'), 'integrated')
        self.now += 1
        self.pipeline.ingest(self.feature('reception1'), 'integrated')
        self.assertEqual(len(self.pipeline.queue), 1)
        asyncio.run(self.pipeline.reconcile())
        self.assertEqual(self.actor.results['reception1']['status'], 'pending')
        self.settle()
        asyncio.run(self.pipeline.reconcile())
        self.assertEqual(self.pipeline.observed['reception1']['status'], 'confirmed')
        self.assertIsNone(self.matched('reception1', 'ehr', 18004).output)
        self.now += 25
        self.pipeline.ingest({'status':'invalid', 'features':[], 'quality':{}}, 'integrated')
        asyncio.run(self.pipeline.reconcile())
        self.settle()
        asyncio.run(self.pipeline.reconcile())
        self.assertEqual(self.pipeline.observed['reception1']['action'], 'RELEASE')
        self.assertEqual(self.pipeline.observed['reception1']['status'], 'confirmed')
        self.assertTrue(any(r['event']['stage'] == 'released' for r in self.pipeline.events))

    def test_every_critical_service_has_a_highest_priority_forward_rule_during_restriction(self):
        self.engine.epoch = 'integrated'
        for name in ('monitor1', 'pump1', 'imaging1', 'nurse1'):
            p = self.engine._proposal(name, 'RESTRICT', int(self.now*1e9), 'Synthetic integration test')
            self.actor.submit(p)
            self.settle()
            self.assertEqual(self.actor.results[name]['status'], 'confirmed')
        for service in self.compiler.settings['critical_services']:
            for source in service['sources']:
                rule = self.matched(source, service['server'], service['port'])
                self.assertIsNotNone(rule, source)
                self.assertEqual(rule.priority, 50000, source)
                self.assertIsNotNone(rule.output, source)
        drop = self.matched('monitor1', 'reception1', 9999)
        self.assertEqual(drop.priority, 40000)
        self.assertIsNone(drop.output)


if __name__ == '__main__':
    unittest.main()
