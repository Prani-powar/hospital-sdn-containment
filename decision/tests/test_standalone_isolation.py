"""Real sklearn training/inference on fixtures; no hospital accuracy or OVS claim."""
import copy
import json
from pathlib import Path
import random
import tempfile
import unittest

from decision.features import FEATURE_FIELDS
from decision.model_contract import ROLES
from decision.train_isolation import train, read_normal
from decision.ml_scoring import MlScorer
from decision.live import LivePipeline, bind_detector
from decision.detection import from_config
from decision.replay_detection import demo_records

ROOT=Path(__file__).resolve().parents[2]


def dataset(path,run,seed,constant=False):
    rng=random.Random(seed);rows=[]
    for role in sorted(ROLES):
        for i in range(35):
            f={k:0 for k in FEATURE_FIELDS}
            n=1 if constant else rng.randint(1,12)
            f.update(host='fixture_'+role,role=role,timestamp_ns=1_000_000_000+i,window_s=5,
                     flow_count=20+n,unique_dst=1 if constant else n%3+1,unique_dst_ports=1 if constant else n%4+1,
                     new_peers=1,pkts_in=n*2,pkts_out=n*2,bytes_in=n*40,bytes_out=n*40,short_flows=n,
                     off_allow_list_flows=0)
            if not constant:
                f.update(pkts_in=rng.randint(10,40),pkts_out=rng.randint(10,40),
                         bytes_in=rng.randint(100,500),bytes_out=rng.randint(100,500),
                         short_flows=rng.randint(1,12))
            rows.append(dict(run_id=run,seed=seed,partition='validation',label='normal',feature=f,
                             quality=dict(valid=True,feature_spec_version='source-ingress-proxy-v1')))
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows));return rows


class StandaloneTests(unittest.TestCase):
    def test_real_fitted_model_loads_without_random_forest_and_drives_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=root/'a.jsonl';b=root/'b.jsonl'
            dataset(a,'fit',101);rows=dataset(b,'cal',102)
            metadata=train([a],[b],root/'model')
            self.assertEqual(metadata['fit_seeds'],[101]);self.assertEqual(metadata['calibration_seeds'],[102])
            self.assertFalse((root/'model/m2_random_forest.joblib').exists())
            scorer=MlScorer.from_directory(root/'model')
            engine=from_config(ROOT/'configs/hospital.yaml',ROOT/'configs/detection.yaml')
            bind_detector(engine,'M1',scorer)
            with self.assertRaisesRegex(ValueError,'Isolation Forest only'):bind_detector(engine,'M2',scorer)
            fixture=next(r for r in demo_records(engine) if r.get('feature',{}).get('host')=='reception1')
            feature=copy.deepcopy(fixture['feature'])
            feature.update(flow_count=1000,unique_dst=20,unique_dst_ports=100,pkts_in=10000,pkts_out=10000,
                           bytes_in=1000000,bytes_out=1000000,new_peers=20,short_flows=1000,off_allow_list_flows=1000)
            self.assertTrue(scorer.score(feature)['m1_anomalous'])
            self.assertNotIn('m2_anomalous',scorer.score(feature))
            pipeline=LivePipeline(engine,None,True,clock=lambda:2_000_000_000)
            for timestamp in (1_000_000_000,2_000_000_000):
                feature['timestamp_ns']=timestamp
                pipeline.ingest(dict(status='ready',features=[copy.deepcopy(feature)],quality=fixture['quality']),'epoch')
            self.assertEqual(len(pipeline.queue),1)
            self.assertEqual(pipeline.queue[0]['action']['action'],'ISOLATE')
            self.assertTrue(pipeline.latest['reception1']['score']['model_version'].startswith('M1:'))
            self.assertFalse(pipeline.observed)  # proposal is not switch confirmation

    def test_tied_constant_normals_do_not_all_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=root/'a';b=root/'b'
            dataset(a,'fit',101,True);rows=dataset(b,'cal',102,True)
            train([a],[b],root/'model')
            scorer=MlScorer.from_directory(root/'model')
            self.assertFalse(scorer.score(rows[0]['feature'])['m1_anomalous'])

    def test_attack_labels_test_seeds_overlap_and_missing_roles_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=root/'a';b=root/'b'
            rows=dataset(a,'fit',101);dataset(b,'cal',101)
            with self.assertRaisesRegex(ValueError,'disjoint'):train([a],[b],root/'bad')
            rows[0]['label']='attack';a.write_text(json.dumps(rows[0])+'\n')
            with self.assertRaises(ValueError):read_normal([a])
            rows[0]['label']='normal';rows[0]['seed']=201;a.write_text(json.dumps(rows[0])+'\n')
            with self.assertRaises(ValueError):read_normal([a])
            rows=dataset(a,'fit',101);dataset(b,'cal',102)
            a.write_text(''.join(json.dumps(r)+'\n' for r in rows if r['feature']['role']=='admin'))
            with self.assertRaisesRegex(ValueError,'20 fit'):train([a],[b],root/'missing')

if __name__=='__main__':unittest.main()
