"""Combined failure/recovery scenarios with stateful fake switches, not OVS."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from controller.core import Fabric
from controller.enforcement import Compiler, Transactions, load_enforcement
from controller.tests.test_enforcement import Switches
from decision.detection import from_config
from topology.hospital import load_plan

ROOT=Path(__file__).resolve().parents[2]


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.now=1.0
        fabric=Fabric(load_plan(ROOT/'configs/hospital.yaml'))
        self.planner=from_config(ROOT/'configs/hospital.yaml',ROOT/'configs/detection.yaml')
        self.planner.epoch='recovery-test'
        compiler=Compiler(fabric,load_enforcement(ROOT/'configs/enforcement.yaml',fabric),self.planner.config)
        self.switch=Switches(fabric,lambda:self.now)
        self.actor=Transactions(compiler,self.switch,'recovery-test',lambda:self.now)
        self.switch.actor=self.actor
        self.finish()

    def finish(self):
        for _ in range(200):
            self.actor.tick();self.switch.drain();self.now+=.1
            if self.actor.active is None and self.actor.ready:return
        self.fail('Fake coordinator did not settle')

    def proposal(self,host,kind,source=None):
        return self.planner._proposal(host,kind,int(self.now*1e9),'Controlled recovery fixture',source)

    def test_mid_drop_disconnect_requires_floor_recovery_and_explicit_scoped_release(self):
        self.actor.submit(self.proposal('reception1','ISOLATE'))
        for _ in range(100):
            self.actor.tick();self.now+=.1
            if self.actor.active['phase']=='drops' and self.actor.active.get('barriers_sent'):
                break
            self.switch.drain()
        self.assertEqual(self.actor.active['phase'],'drops')
        old=self.switch.dp.pop(0x11)
        self.actor.tick()
        self.assertEqual(self.actor.results['reception1']['status'],'failed')
        self.assertFalse(self.actor.ready)
        self.assertEqual(self.actor.submit(self.proposal('guest1','ISOLATE'))[0],409)
        # A restarted switch loses only its own table; stale replies remain queued.
        self.switch.table={k:v for k,v in self.switch.table.items() if k[0]!=old.id}
        self.switch.dp[old.id]=SimpleNamespace(id=old.id)
        self.finish()
        self.assertTrue(self.actor.ready)
        self.assertEqual(self.actor.results['reception1']['status'],'failed')
        self.assertFalse(any(r['event']['stage']=='rule_installed' for r in self.actor.events))
        self.actor.submit(self.proposal('reception1','RELEASE'));self.finish()
        self.assertEqual(self.actor.results['reception1']['status'],'confirmed')
        self.assertEqual({r.identity for r,_ in self.switch.table.values()},
                         {r.identity for r in self.actor.compiler.floor})

    def test_release_of_one_host_keeps_other_host_containment_and_all_critical_rules(self):
        self.actor.submit(self.proposal('guest1','ISOLATE'));self.finish()
        self.actor.submit(self.proposal('monitor1','RESTRICT'));self.finish()
        before={r.identity for r,_ in self.switch.table.values() if
                r.cookie&0xFFFFFF0000000000==self.actor.compiler.namespace('monitor1')}
        self.actor.submit(self.proposal('guest1','RELEASE'));self.finish()
        after={r.identity for r,_ in self.switch.table.values() if
               r.cookie&0xFFFFFF0000000000==self.actor.compiler.namespace('monitor1')}
        self.assertEqual(before,after)
        self.assertTrue(before)
        self.assertTrue({r.identity for r in self.actor.compiler.floor}<=
                        {r.identity for r,_ in self.switch.table.values()})

    def test_ttl_expiry_racing_release_confirms_absence_without_removing_floor(self):
        self.actor.submit(self.proposal('reception1','ISOLATE'));self.finish()
        self.now += 39
        proposal=self.proposal('reception1','RELEASE')
        self.actor.submit(proposal)
        # Simulate TTL expiration while scoped inventory requests are pending.
        self.now += 2
        self.finish()
        self.assertEqual(self.actor.results['reception1']['status'],'confirmed')
        self.assertEqual(self.actor.results['reception1']['action'],'RELEASE')
        self.assertEqual({r.identity for r,_ in self.switch.table.values()},
                         {r.identity for r in self.actor.compiler.floor})
