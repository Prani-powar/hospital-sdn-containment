"""Synthetic report/audit fixtures test consistency; they are not measured lab results."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.summarize_demo import VARIANT, export, markdown, read_events, read_json, summarize
from scripts.tests.test_demo import phases, actions


def fixture():
    p=phases()
    for row in p.values():
        row['clinical'].update(run_id='a'*32,variant=VARIANT,start_ns=row['start_ns'],end_ns=row['end_ns'])
        for service in row['clinical']['services']:
            for source in service['sources']:
                source.update(mean_rtt_ms=.5,minimum_expected_probes=1)
    return {'check':'hospital_demo_report','schema_version':1,'run_id':'a'*32,
        'mode':'enforce','status':'PASS','phases':p,'confirmed_actions':actions(),
        'error':None,'cleanup_errors':[],
        'offered_probe':{'check':'storm_probe_finished','host':'reception1','attempted':64,
            'send_errors':0,'elapsed_s':16.0,'offered_packets_per_s':4.0}}


def event(stage,stamp,details,host='reception1'):
    return {'run_id':'a'*32,'timestamp_ns':stamp,'stage':stage,'host':host,'details':details}


class SummaryTests(unittest.TestCase):
    def test_counts_are_phase_scoped_and_rtt_uses_reply_weights(self):
        report=fixture()
        sources=report['phases']['baseline']['clinical']['services'][0]['sources']
        sources[0].update(attempted=20,received=20,mean_rtt_ms=2)
        summary=summarize(report)
        self.assertEqual(summary['evidence_status'],'PASS')
        row=summary['rows'][0]
        self.assertEqual((row['attempted'],row['received']),(40,40))
        self.assertEqual(row['mean_rtt_ms'],1.25)
        text=markdown(summary)
        self.assertIn('not the entire traffic session',text)
        self.assertIn('unmeasured',text)

    def test_saved_pass_cannot_hide_loss_wrong_run_missing_probe_or_insufficient_coverage(self):
        for kind in ('loss','wrong_run','interval','probe_missing','probe_rate','coverage','cleanup'):
            report=fixture()
            row=report['phases']['restricted']['clinical']
            if kind=='loss':row['services'][0]['sources'][0]['received']=9
            elif kind=='wrong_run':row['run_id']='b'*32
            elif kind=='interval':row['start_ns']+=1
            elif kind=='probe_missing':report['offered_probe']=None
            elif kind=='probe_rate':report['offered_probe']['offered_packets_per_s']=500
            elif kind=='coverage':row['services'][0]['sources'][0]['minimum_expected_probes']=11
            else:report['cleanup_errors']=['Owned worker did not stop']
            summary=summarize(report)
            self.assertEqual(summary['evidence_status'],'FAIL',kind)
            self.assertFalse(summary['consistent'],kind)
        report=fixture();report['status']='FAIL'
        self.assertEqual(summarize(report)['evidence_status'],'FAIL')

    def test_latency_requires_matching_proposal_host_and_readback_evidence(self):
        proposal='a'*64
        records=[event('attack_start',1,{'scope':'owned_probe_process_launch'}),
                 event('rule_requested',5,{'proposal_id':proposal}),
                 event('rule_installed',20,{'proposal_id':proposal,'readback_confirmed':True})]
        row=summarize(fixture(),records)['action_timings'][0]
        self.assertEqual(row['request_to_readback_s'],15e-9)
        self.assertEqual(row['probe_launch_to_readback_s'],19e-9)
        release_records=records+[event('rule_requested',45,{'proposal_id':'b'*64}),
                                 event('released',50,{'proposal_id':'b'*64,'readback_confirmed':True})]
        self.assertEqual(summarize(fixture(),release_records)['action_timings'][1]['request_to_readback_s'],5e-9)
        records[-1]['host']='monitor1'
        self.assertIsNone(summarize(fixture(),records)['action_timings'][0]['request_to_readback_s'])
        records[-1]['host']='reception1';records[-1]['details']['readback_confirmed']=False
        self.assertIsNone(summarize(fixture(),records)['action_timings'][0]['request_to_readback_s'])

    def test_varied_source_is_reassessed_and_wrong_probe_host_rejected(self):
        for name,kind in [('billing1','ISOLATE'),('monitor2','RESTRICT')]:
            report=fixture();report.update(source_host=name,containment_action=kind)
            report['offered_probe']['host']=name
            for row in report['confirmed_actions']:
                row['host']=name
                if row['action']=='ISOLATE':row['action']=kind
            self.assertEqual(summarize(report)['evidence_status'],'PASS')
            report['offered_probe']['host']='reception1'
            self.assertEqual(summarize(report)['evidence_status'],'FAIL')

    def test_audit_rejects_mixed_runs_and_malformed_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'events.jsonl'
            valid=event('attack_start',1,{'scope':'owned_probe_process_launch'})
            path.write_text(json.dumps(valid)+'\n')
            self.assertEqual(len(read_events([path],'a'*32)),1)
            with self.assertRaises(ValueError):read_events([path],'b'*32)
            invalid=dict(valid,extra=1);path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):read_events([path],'a'*32)
            with self.assertRaises(ValueError):read_events([path]*3,'a'*32)

    def test_export_is_exclusive_and_preserves_source_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'report.json';path.write_text(json.dumps(fixture()))
            result=export(path,root/'summary')
            self.assertEqual(len(result['report_sha256']),64)
            self.assertEqual(len((root/'summary'/'clinical.csv').read_text().splitlines()),16)
            self.assertTrue((root/'summary'/'summary.md').exists())
            with self.assertRaises(FileExistsError):export(path,root/'summary')
            self.assertEqual(read_json(path)[1],result['report_sha256'])

    def test_corrupt_counts_nan_and_unknown_phases_are_rejected(self):
        for update in ('nan','counts','phase'):
            report=fixture()
            if update=='counts':report['phases']['baseline']['clinical']['services'][0]['sources'][0]['received']=-1
            elif update=='phase':report['phases']['unrecognized']={}
            else:
                with tempfile.TemporaryDirectory() as tmp:
                    path=Path(tmp)/'bad.json';path.write_text('{"x":NaN}')
                    with self.assertRaises(ValueError):read_json(path)
                continue
            with self.assertRaises(ValueError):summarize(report)
