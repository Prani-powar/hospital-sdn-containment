"""Stateful fake OpenFlow switch tests; no real OVS/installation claim."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest

from controller.core import Fabric
from controller.enforcement import ACTION_PREFIX, FLOOR_MASK, Compiler, Transactions, load_enforcement
from decision.detection import DetectionPolicy, load_detection_config
from topology.hospital import load_plan

ROOT=Path(__file__).resolve().parents[2]


class Switches:
    def __init__(self,fabric,clock):
        self.dp={d:SimpleNamespace(id=d) for d in fabric.switches}
        self.clock=clock;self.xid=0;self.table={};self.pending=[];self.commands=[]
        self.reject=False;self.drop_readback=False;self.actor=None;self.immediate=False

    def connections(self):return self.dp

    def prepare(self,kind,dpid,**args):
        self.xid+=1
        return SimpleNamespace(kind=kind,dp=self.dp[dpid],xid=self.xid,args=args)

    def queue(self,h):
        if self.reject:return False
        self.commands.append(h)
        if h.kind in ('add','delete'):
            r=h.args['rule'];key=(r.dpid,r.priority,r.match_json)
            if h.kind=='add':self.table[key]=(r,self.clock())
            elif key in self.table and self.table[key][0].cookie==r.cookie:del self.table[key]
        else:
            self.pending.append(h)
            if self.immediate:self.drain_one()
        return True

    def drain_one(self):
        h=self.pending.pop(0)
        rows=[]
        if h.kind=='stats':
            for key,(rule,created) in list(self.table.items()):
                if rule.hard_timeout and self.clock()>=created+rule.hard_timeout:
                    del self.table[key];continue
                if rule.dpid==h.dp.id and rule.cookie&h.args['mask']==h.args['cookie']&h.args['mask']:
                    rows.append(rule.row())
            if self.drop_readback and rows:rows.pop()
        self.actor.reply(h.kind,h.dp.id,h.xid,h.dp,rows)

    def drain(self):
        while self.pending:self.drain_one()


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.fabric=Fabric(load_plan(ROOT/'configs/hospital.yaml'))
        self.settings=load_enforcement(ROOT/'configs/enforcement.yaml',self.fabric)
        self.policy=load_detection_config(ROOT/'configs/detection.yaml',self.fabric)
        self.compiler=Compiler(self.fabric,self.settings,self.policy)
        self.time=0.0
        self.switch=Switches(self.fabric,lambda:self.time)
        self.actor=Transactions(self.compiler,self.switch,'test-epoch',lambda:self.time)
        self.switch.actor=self.actor
        self.planner=DetectionPolicy(self.fabric,self.policy);self.planner.epoch='test-epoch'
        self.finish()

    def finish(self,limit=300):
        for _ in range(limit):
            self.actor.tick();self.switch.drain();self.time+=0.1
            if self.actor.active is None and self.actor.ready:return
        self.fail('Transaction did not settle')

    def proposal(self,host='reception1',kind='ISOLATE',source=None):
        return self.planner._proposal(host,kind,int(self.time*1e9),'controlled test',source)

    def test_floor_is_confirmed_before_first_action_and_survives_release(self):
        self.assertTrue(self.actor.ready)
        floor={r.cookie for r,_ in self.switch.table.values()}
        self.assertTrue(floor)
        self.assertTrue(all(r.priority==50000 and r.hard_timeout==0 for r,_ in self.switch.table.values()))
        code,result=self.actor.submit(self.proposal());self.assertEqual(code,202)
        self.assertEqual(result['status'],'pending')
        self.finish()
        self.assertEqual(self.actor.results['reception1']['status'],'confirmed')
        self.actor.submit(self.proposal(kind='RELEASE'));self.finish()
        self.assertEqual({r.cookie for r,_ in self.switch.table.values()},floor)
        self.assertEqual(self.actor.events[-1]['event']['stage'],'released')
        deletes=[h.args['rule'] for h in self.switch.commands if h.kind=='delete']
        self.assertTrue(all(r.cookie&FLOOR_MASK==ACTION_PREFIX and r.priority<50000 for r in deletes))

    def test_allows_precede_ingress_drop_then_propagation(self):
        start=len(self.switch.commands)
        proposal=self.proposal('monitor1','RESTRICT')
        self.actor.submit(proposal);self.finish()
        adds=[h.args['rule'] for h in self.switch.commands[start:] if h.kind=='add']
        first_drop=next(i for i,r in enumerate(adds) if r.priority==40000)
        self.assertTrue(all(r.priority==45000 for r in adds[:first_drop]))
        self.assertEqual(adds[first_drop].dpid,self.fabric.hosts['monitor1']['access_dpid'])
        self.assertTrue(all(r.hard_timeout>0 for r in adds))
        self.assertGreater(min(r.hard_timeout for r in adds if r.priority==45000),
                           max(r.hard_timeout for r in adds if r.priority==40000))

    def test_every_protected_role_rejects_isolation_and_missing_vital_peer(self):
        for name,host in self.fabric.hosts.items():
            if host['role'] not in ('clinical','iomt','critical_server'):continue
            p=self.proposal('reception1');p['action']['host']=name
            with self.assertRaises(ValueError):self.compiler.compile(p,'test-epoch')
        p=self.proposal('monitor1','RESTRICT');p['action']['allowed_peers']=['dns_ad']
        with self.assertRaises(ValueError):self.compiler.compile(p,'test-epoch')

    def test_protect_targets_attacker_source_and_rejects_critical_conflict(self):
        p=self.proposal('ehr','PROTECT','guest1')
        _,rules=self.compiler.compile(p,'test-epoch')
        self.assertEqual(rules[0].dpid,self.fabric.hosts['guest1']['access_dpid'])
        self.assertTrue(all(r.match['ipv4_src']=='10.20.0.22' and r.match['ipv4_dst']=='10.20.0.11' for r in rules))
        p['malicious_source']='doctor1'
        with self.assertRaises(ValueError):self.compiler.compile(p,'test-epoch')

    def test_duplicate_id_is_idempotent_content_conflict_and_stale_version_rejected(self):
        p=self.proposal();self.actor.submit(p);before=len(self.switch.commands)
        code,body=self.actor.submit(copy.deepcopy(p));self.assertEqual(code,202)
        self.assertEqual(len(self.switch.commands),before)
        changed=copy.deepcopy(p);changed['action']['reason']='changed'
        with self.assertRaises(ValueError):self.actor.submit(changed)
        self.finish();code,_=self.actor.submit(p);self.assertEqual(code,200)
        stale=copy.deepcopy(p);stale['proposal_id']='f'*64
        with self.assertRaises(ValueError):self.actor.submit(stale)

    def test_new_owner_and_wrong_controller_epoch_rejected(self):
        p=self.proposal();self.actor.submit(p);self.finish()
        p=self.proposal(kind='RELEASE');p['planner_epoch']='a'*32
        with self.assertRaises(ValueError):self.actor.submit(p)
        p=self.proposal(kind='RELEASE');p['controller_epoch']='obsolete'
        with self.assertRaises(ValueError):self.actor.submit(p)

    def test_busy_request_does_not_consume_host_version(self):
        p=self.proposal();self.actor.submit(p)
        p2=self.proposal('guest1')
        code,_=self.actor.submit(p2);self.assertEqual(code,409)
        self.assertNotIn('guest1',self.actor.results)
        self.finish();self.assertEqual(self.actor.submit(p2)[0],202);self.finish()

    def test_readback_mismatch_never_emits_installed(self):
        self.switch.drop_readback=True
        self.actor.submit(self.proposal())
        self.finish()
        self.assertEqual(self.actor.results['reception1']['status'],'failed')
        self.assertFalse(any(e['event']['stage']=='rule_installed' for e in self.actor.events))

    def test_deadline_disconnect_error_and_send_failure_are_not_success(self):
        for kind in ('deadline','disconnect','error','send'):
            self.setUp();self.actor.submit(self.proposal())
            if kind=='deadline':self.time+=20;self.actor.tick()
            elif kind=='disconnect':self.switch.dp.pop(0x11);self.actor.tick()
            elif kind=='error':
                pending=next(iter(self.actor.active['pending']))
                self.actor.error(*pending,self.switch.dp[pending[0]])
            else:
                self.switch.drain();self.switch.reject=True;self.actor.tick()
            self.assertEqual(self.actor.results['reception1']['status'],'failed',kind)
            self.assertFalse(any(e['event']['stage']=='rule_installed' for e in self.actor.events))

    def test_replacement_uses_full_cookie_strict_deletion_without_deleting_new_rules(self):
        self.actor.submit(self.proposal('vendor_gw','RESTRICT'));self.finish()
        new=self.proposal('vendor_gw','ISOLATE')
        self.actor.submit(new);self.finish()
        _,expected=self.compiler.compile(new,'test-epoch')
        actual=[r for r,_ in self.switch.table.values() if r.cookie&0xFFFFFF0000000000==self.compiler.namespace('vendor_gw')]
        self.assertEqual({r.identity for r in actual},{r.identity for r in expected})

    def test_multipart_bounds_and_obsolete_reply(self):
        self.actor.submit(self.proposal())
        key,pending=next(iter(self.actor.active['pending'].items()))
        self.assertFalse(self.actor.reply('stats',*key,SimpleNamespace(id=key[0]),[]))
        self.actor.error(*key,SimpleNamespace(id=key[0]))
        self.assertIsNotNone(self.actor.active)
        for _ in range(self.settings['max_parts']+1):
            self.actor.reply('stats',*key,pending['dp'],[],True)
        self.assertEqual(self.actor.results['reception1']['status'],'failed')

    def test_synchronous_replies_cannot_advance_a_partially_registered_batch(self):
        self.switch.immediate=True
        self.actor.submit(self.proposal());self.finish()
        self.assertEqual(self.actor.results['reception1']['status'],'confirmed')
        self.assertEqual(self.actor.events[-1]['event']['stage'],'rule_installed')


if __name__=='__main__':unittest.main()
