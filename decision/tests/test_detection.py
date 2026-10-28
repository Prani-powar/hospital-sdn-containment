"""Role safety, evidence integrity and desired-policy hysteresis tests."""
import copy
from pathlib import Path
import tempfile
import unittest

import yaml

from decision.detection import from_config, load_detection_config
from decision.replay_detection import demo_records, replay

ROOT = Path(__file__).resolve().parents[2]
NS = 1_000_000_000


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.engine = from_config(ROOT/'configs'/'hospital.yaml', ROOT/'configs'/'detection.yaml')
        self.quality = {'valid': True, 'feature_spec_version': 'source-ingress-proxy-v1',
                        'profile_version': 'hospital-peer-profile-v1'}

    def feature(self, name='reception1', second=1, anomalous=True):
        role = self.engine.fabric.hosts[name]['role']
        t = self.engine.config['thresholds'][role]
        dst, ports = (t['unique_dst'], t['unique_dst_ports']) if anomalous else (1, 1)
        return dict(timestamp_ns=second*NS, window_s=5, host=name, role=role,
                    flow_count=max(dst, ports), unique_dst=dst, unique_dst_ports=ports,
                    bytes_in=0, bytes_out=1000, pkts_in=0, pkts_out=10,
                    new_peers=dst, off_allow_list_flows=1 if anomalous else 0, short_flows=0)

    def consume(self, name='reception1', second=1, anomalous=True, epoch='a', **kwargs):
        return self.engine.consume(self.feature(name, second, anomalous), self.quality, second*NS, epoch, **kwargs)

    def contain(self, name='reception1', **kwargs):
        self.consume(name, 1, **kwargs)
        return self.consume(name, 2, **kwargs)

    def test_exact_score_action_contract_and_consecutive_confirmation(self):
        one = self.consume()
        self.assertEqual(one['proposals'], [])
        self.assertEqual(set(one['score']), {'host','anomaly_score','anomalous','model_version'})
        result = self.consume(second=2)
        p = result['proposals'][0]
        self.assertEqual(set(p['action']), {'action','host','allowed_peers','timeout_s','reason'})
        self.assertEqual(p['action']['action'], 'ISOLATE')
        self.assertFalse(p['applied'])
        self.assertGreater(p['action']['timeout_s'], 0)
        self.assertEqual(p['action']['allowed_peers'], ['dns_ad'])
        self.assertEqual(len(p['proposal_id']), 64)
        other=from_config(ROOT/'configs'/'hospital.yaml',ROOT/'configs'/'detection.yaml')
        other.consume(self.feature(second=1),self.quality,NS,'a')
        new=other.consume(self.feature(second=2),self.quality,2*NS,'a')['proposals'][0]
        self.assertNotEqual(p['proposal_id'],new['proposal_id'])

    def test_all_clinical_and_iomt_hosts_never_automatically_isolate(self):
        for name, h in self.engine.fabric.hosts.items():
            if h['role'] not in ('clinical','iomt'):
                continue
            result = self.contain(name)
            self.assertEqual(result['proposals'][0]['action']['action'], 'RESTRICT', name)
            for t in range(3,9):
                self.assertFalse(self.consume(name,t)['proposals'], name)
            with self.assertRaises(ValueError):
                self.engine._proposal(name,'ISOLATE',9*NS,'unsafe test')

    def test_critical_server_requires_source_and_preserves_vital_allow(self):
        for name, h in self.engine.fabric.hosts.items():
            if h['role'] != 'critical_server':
                continue
            self.assertEqual(self.contain(name)['status'], 'needs_source_attribution_or_human_review')
            with self.assertRaises(ValueError):
                self.engine._proposal(name,'ISOLATE',3*NS,'unsafe test')
        result = self.consume('ehr',3,malicious_source='doctor1')
        self.assertEqual(result['proposals'], [])
        result = self.consume('ehr',4,malicious_source='guest1')
        self.assertEqual(result['proposals'][0]['action']['action'],'PROTECT')
        self.assertEqual(result['proposals'][0]['malicious_source'],'guest1')

    def test_vendor_escalates_only_after_additional_confirmed_windows(self):
        self.assertEqual(self.contain('vendor_gw')['proposals'][0]['action']['action'],'RESTRICT')
        self.assertFalse(self.consume('vendor_gw',3)['proposals'])
        self.assertFalse(self.consume('vendor_gw',4)['proposals'])
        result = self.consume('vendor_gw',5)
        self.assertEqual(result['proposals'][0]['action']['action'],'ISOLATE')
        self.assertEqual(result['proposals'][0]['version'],2)

    def test_duplicate_and_out_of_order_windows_cannot_trigger_or_renew(self):
        self.consume()
        for _ in range(4):
            self.assertEqual(self.consume()['status'],'duplicate_or_stale')
        self.assertIsNone(self.engine.states['reception1'].action)
        self.consume(second=2)
        expiry = self.engine.states['reception1'].lease_until_ns
        self.consume(second=2)
        self.assertEqual(self.engine.states['reception1'].lease_until_ns,expiry)

    def test_invalid_missing_and_gapped_windows_break_streaks(self):
        self.consume()
        bad = dict(self.quality,valid=False)
        self.engine.consume(self.feature(second=2),bad,2*NS,'a')
        self.assertFalse(self.consume(second=3)['proposals'])
        self.assertFalse(self.consume(second=10)['proposals'])
        self.assertEqual(self.consume(second=11)['proposals'][0]['action']['action'],'ISOLATE')
        self.engine.invalidate()
        self.assertEqual(self.engine.states['reception1'].action,'ISOLATE')

    def test_clean_release_and_invalid_data_does_not_count_as_clean(self):
        self.contain()
        self.consume(second=3,anomalous=False)
        self.engine.invalidate('reception1')
        self.assertFalse(self.consume(second=4,anomalous=False)['proposals'])
        self.assertFalse(self.consume(second=5,anomalous=False)['proposals'])
        result = self.consume(second=6,anomalous=False)
        self.assertEqual(result['proposals'][0]['action']['action'],'RELEASE')
        self.assertFalse(self.engine.tick(100*NS))

    def test_lease_expires_without_new_telemetry_and_never_claims_installed_state(self):
        self.contain()
        self.assertFalse(self.engine.tick(21*NS))
        result = self.engine.tick(22*NS)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['action']['action'],'RELEASE')
        self.assertFalse(result[0]['applied'])
        self.assertFalse(self.engine.tick(23*NS))

    def test_epoch_change_breaks_streaks_without_forgetting_desired_lease(self):
        self.consume()
        self.assertFalse(self.consume(second=2,epoch='b')['proposals'])
        self.consume(second=3,epoch='b')
        expiry = self.engine.states['reception1'].lease_until_ns
        self.consume(second=4,epoch='c')
        self.assertEqual(self.engine.states['reception1'].lease_until_ns,expiry)

    def test_normal_busy_role_and_port_scan_detection(self):
        f = self.feature('ehr')
        f['off_allow_list_flows'] = 0
        self.assertFalse(self.engine.consume(f,self.quality,NS,'a')['score']['anomalous'])
        f = self.feature(second=2)
        f['unique_dst'] = f['new_peers'] = 1
        self.assertTrue(self.engine.consume(f,self.quality,2*NS,'a')['score']['anomalous'])

    def test_spoofed_stale_nan_and_inconsistent_features_fail_closed(self):
        for key,value in [('role','guest'),('window_s',float('nan')),('pkts_out',True),
                          ('timestamp_ns',10*NS),('new_peers',100),('host',['invalid'])]:
            self.setUp()
            f=self.feature(); f[key]=value
            result=self.engine.consume(f,self.quality,NS,'a')
            self.assertEqual(result['status'],'invalid',key)
            self.assertFalse(result['proposals'])
        self.assertEqual(self.engine.consume(self.feature(),self.quality,10*NS,'a')['status'],'invalid')

    def test_config_cannot_remove_vital_peer_or_add_unknown_role(self):
        for mutate in ('peer','role','ttl','nan'):
            c=copy.deepcopy(self.engine.config)
            if mutate=='peer': c['allowed_peer_overrides']['monitor1']=['dns_ad']
            elif mutate=='role': c['thresholds']['unknown']={}
            elif mutate=='ttl': c['containment_timeout_s']=0
            else: c['max_step_gap_s']=float('nan')
            with tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'config.yaml';p.write_text(yaml.safe_dump(c))
                with self.assertRaises(ValueError): load_detection_config(p,self.engine.fabric)

    def test_state_is_fixed_inventory_and_streaks_are_capped(self):
        for t in range(1,150): self.consume(second=t)
        self.assertEqual(len(self.engine.states),24)
        self.assertLessEqual(self.engine.states['reception1'].anomalous_streak,2)

    def test_offline_replay_runs_real_logic_without_enforcement_events(self):
        events=[]
        summary=replay(demo_records(self.engine),self.engine,events.append)
        self.assertEqual(summary['network_actions_sent'],0)
        self.assertEqual(summary['proposed_actions'],{'ISOLATE':3,'RESTRICT':3,'RELEASE':5})
        self.assertTrue(all(e['stage'] in ('scored','decision') for e in events))
        self.assertTrue(all(e['details']['applied'] is False for e in events))
        self.assertTrue(any(e['details'].get('proposal',{}).get('action',{}).get('host')=='monitor1' for e in events))

    def test_actual_feature_extractor_to_detector_and_role_policy(self):
        from decision.tests import test_features as fixtures
        for source, expected in [('reception1','ISOLATE'),('monitor1','RESTRICT')]:
            self.setUp()
            fixture=fixtures.FeatureTests(); fixture.setUp()
            fixture.ingest(10)
            observations=[]
            destinations=[h for h in self.engine.fabric.hosts if h not in (source,'dns_ad','central_mon')][:8]
            decisions=[]
            for t in (11,12,13):
                for i in range(16):
                    observations.append(fixture.obs(len(observations)+1,t,host=source,
                        dst=destinations[i%8],port=20000+i))
                result=fixture.ingest(t,obs=observations)
                for feature in result['features']:
                    if feature['host']==source:
                        result_policy=self.engine.consume(feature,result['quality'],feature['timestamp_ns'],'pipeline')
                        decisions.extend(result_policy['proposals'])
            self.assertEqual(len(decisions),1)
            self.assertEqual(decisions[0]['action']['action'],expected)
            self.assertFalse(decisions[0]['applied'])


if __name__=='__main__': unittest.main()
