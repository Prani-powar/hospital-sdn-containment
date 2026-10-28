import asyncio
import copy
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from decision.detection import from_config
from decision.live import LivePipeline, bind_detector
from decision.replay_detection import demo_records
from experiments.agents import normal_peers, run as run_agent
from experiments.baselines import blind_rules, static_rules, OwnedRules
from experiments.configuration import prepare
from experiments.dataset import label
from experiments.matrix import cases, command
from experiments.metrics import latencies, summarize
from controller.core import Fabric
from controller.enforcement import load_enforcement
from topology.hospital import load_plan

ROOT=Path(__file__).resolve().parents[2]

class ResearchTests(unittest.TestCase):
    def test_selected_ml_drives_real_policy_even_when_m3_is_clean(self):
        for detector in ('M1','M2'):
            engine=from_config(ROOT/'configs/hospital.yaml',ROOT/'configs/detection.yaml')
            scorer=SimpleNamespace(score=lambda f:dict(m1_anomalous=True,m2_anomalous=True,
                m1_raw_anomaly_score=.7,m2_attack_probability=.9,model_artifact_created_at='fixture'))
            bind_detector(engine,detector,scorer)
            fixture=next(r for r in demo_records(engine) if r.get('feature',{}).get('host')=='reception1')
            pipeline=LivePipeline(engine,None,True,clock=lambda:2_000_000_000)
            f=copy.deepcopy(fixture['feature']);f.update(unique_dst=0,unique_dst_ports=0,off_allow_list_flows=0,new_peers=0)
            for stamp in (1_000_000_000,2_000_000_000):
                f['timestamp_ns']=stamp
                pipeline.ingest({'status':'ready','features':[copy.deepcopy(f)],'quality':fixture['quality']},'epoch')
            self.assertEqual(pipeline.queue[0]['action']['action'],'ISOLATE')
            self.assertTrue(pipeline.latest['reception1']['score']['model_version'].startswith(detector))
            self.assertFalse(pipeline.observed)

    def test_missing_or_broken_ml_never_falls_back(self):
        engine=from_config(ROOT/'configs/hospital.yaml',ROOT/'configs/detection.yaml')
        with self.assertRaises(ValueError):bind_detector(engine,'M1')
        bind_detector(engine,'M2',SimpleNamespace(score=lambda f: {}))
        fixture=next(r for r in demo_records(engine) if 'feature' in r)
        result=engine.consume(fixture['feature'],fixture['quality'],fixture['feature']['timestamp_ns'],'epoch')
        self.assertEqual(result['status'],'invalid');self.assertEqual(result['proposals'],[])

    def test_scalability_configs_validate(self):
        for count in (12,24,48):
            with tempfile.TemporaryDirectory() as tmp:
                topology,paths=prepare(ROOT,Path(tmp),count)
                self.assertEqual(len(topology['hosts']),count)
                from_config(paths['topology'],paths['policy'])
                from decision.features import from_files
                from_files(paths['topology'],paths['features'])
                self.assertEqual(len(blind_rules(topology,'monitor1',40)),12)
                self.assertTrue(all('priority=62000' in r and '18001' not in r for _,r in blind_rules(topology,'monitor1',40)))

    def test_static_rules_keep_service_exception_above_drop(self):
        topology=load_plan(ROOT/'configs/hospital.yaml')
        rows=static_rules(topology,[dict(sources=['monitor1'],server='central_mon',udp_port=18001)])
        self.assertTrue(any('tp_dst=18001' in r and 'priority=60000' in r for _,r in rows))
        self.assertTrue(any('priority=59000' in r and 'actions=drop' in r for _,r in rows))

    def test_rule_readback_is_match_sensitive(self):
        body='priority=62000,ip,nw_src=10.20.0.1,hard_timeout=40,actions=drop'
        self.assertTrue(OwnedRules.matches(' cookie=0xe7, duration=0.1s, table=0, priority=62000,ip,nw_src=10.20.0.1,hard_timeout=40 actions=drop',body))
        self.assertFalse(OwnedRules.matches(' priority=62000,ip,nw_src=10.20.0.2,hard_timeout=40 actions=drop',body))

    def test_missing_detection_is_not_zero_latency(self):
        self.assertIsNone(latencies(10,None,None)['time_to_contain_s'])
        self.assertAlmostEqual(latencies(10,1_000_000_010,2_000_000_010)['time_to_contain_s'],2)
        with self.assertRaises(ValueError):latencies(10,30,20)

    def test_seed_separation_and_matrix_coverage(self):
        validation=list(cases());test=list(cases('test'))
        self.assertEqual(len(validation),240)
        self.assertFalse({r['seed'] for r in validation}&{r['seed'] for r in test})
        self.assertEqual({r['rate'] for r in validation if r['scenario']=='S2'},{.5,1,2,4})
        self.assertEqual({r['hosts'] for r in cases(scalability=True)},{12,24,48})
        self.assertIn('--warmup',command(validation[0]))

    def test_labels_exclude_boundary_and_censored_windows(self):
        def f(end):return dict(feature=dict(host='h',timestamp_ns=end,window_s=1),quality=dict(valid=True))
        truth=[dict(stage='infection_marker',host='h',timestamp_ns=2_500_000_000)]
        rows=label([f(2_000_000_000),f(3_000_000_000),f(4_000_000_000),f(5_000_000_000)],truth,
                   [dict(stage='rule_installed',host='h',timestamp_ns=4_500_000_000)],0,6_000_000_000)
        self.assertEqual([r['label'] for r in rows],['normal','attack'])

    def test_marker_receipt_and_normal_reply_use_real_udp(self):
        topology={'hosts':[dict(name='a',ip='127.0.0.2/8',role='admin'),dict(name='dns_ad',ip='127.0.0.3/8',role='critical_server')]}
        failures=[]
        def worker(args):
            try:run_agent(args)
            except Exception as exc:failures.append(exc)
        with tempfile.TemporaryDirectory() as tmp, patch('experiments.agents.load_plan',return_value=topology):
            args=[SimpleNamespace(topology=Path('fixture'),host=h,source='a',run_id='a'*32,seed=101,scenario='S1',
                      rate=4,duration=1.5,attack_after=.2,output=Path(tmp)/(h+'.jsonl')) for h in ('a','dns_ad')]
            threads=[threading.Thread(target=worker,args=(a,)) for a in args]
            for t in threads:t.start()
            for t in threads:t.join(timeout=5)
            self.assertFalse(failures)
            rows=[json.loads(l) for l in (Path(tmp)/'dns_ad.jsonl').read_text().splitlines()]
            self.assertTrue(any(r['stage']=='infection_marker' and r['details']['source']=='a' for r in rows))
            rows=[json.loads(l) for l in (Path(tmp)/'a.jsonl').read_text().splitlines()]
            self.assertTrue(any(r['stage']=='normal_reply' for r in rows))

if __name__=='__main__':unittest.main()
