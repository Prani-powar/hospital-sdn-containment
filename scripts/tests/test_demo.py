"""Finite demonstration gates and ownership checks without Docker or Mininet."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.demo import Demo, assess, choose_source
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]


def phases():
    endpoints = {'C1':['monitor1','monitor2','monitor3'],'C2':['pump1','pump2'],
        'C3':['imaging1'],'C4':['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'],'C5':['lis']}
    result = {}
    for name,start,end in [('baseline',1,10),('restricted',30,40),('recovered',60,70)]:
        services = [{'flow_id':flow,'sources':[{'source':source,'attempted':10,'received':10,
                      'invalid_records':0,'status':'PASS'} for source in sources]}
                    for flow,sources in endpoints.items()]
        result[name] = {'start_ns':start,'end_ns':end,
            'clinical':{'status':'PASS','services':services},
            'ping':{'executed':True,'exit_code':1 if name=='restricted' else 0}}
    return result


def actions():
    return [{'host':'reception1','action':kind,'status':'confirmed','confirmed_ns':stamp,
             'proposal_id':char*64} for kind,stamp,char in [('ISOLATE',20,'a'),('RELEASE',50,'b')]]


class DemoTests(unittest.TestCase):
    def test_validate_only_runs_without_root_or_network(self):
        result = subprocess.run([sys.executable,'scripts/demo.py','--validate-only','--enforce'],
                                cwd=ROOT,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body['sources'],13)
        self.assertEqual(body['worker_processes'],18)
        self.assertFalse(body['network_started'])

    def test_all_five_services_and_real_action_order_required(self):
        self.assertEqual(assess(phases(),True,actions()),'PASS')
        self.assertEqual(assess({},False,[]),'FAIL')
        self.assertEqual(assess(phases(),False,[]),'OBSERVATION_ONLY')
        for kind in ('missing_service','missing_source','loss','empty','ping_error','no_ping'):
            value = phases()
            phase = value['restricted']
            if kind=='missing_service':
                phase['clinical']['services'].pop()
            elif kind=='missing_source':
                phase['clinical']['services'][0]['sources'].pop()
            elif kind=='loss':
                phase['clinical']['services'][0]['sources'][0]['received']=9
            elif kind=='empty':
                phase['clinical']['services'][0]['sources'][0].update(attempted=0,received=0)
            elif kind=='ping_error':
                phase['ping']['exit_code']=2
            else:
                phase['ping']['executed']=False
            self.assertEqual(assess(value,True,actions()),'FAIL',kind)

    def test_stale_pending_identical_or_mistimed_actions_never_pass(self):
        for updates in ({'status':'pending'},{'confirmed_ns':1}, {'proposal_id':'bad'},
                        {'host':'monitor1'}, {'proposal_id':'b'*64}):
            value = actions()
            value[0].update(updates)
            self.assertEqual(assess(phases(),True,value),'FAIL',updates)
        self.assertEqual(assess(phases(),True,[]),'FAIL')

    def test_host_selection_and_role_correct_action(self):
        topology=load_plan(ROOT/'configs/hospital.yaml')
        for name,kind in [('billing1','ISOLATE'),('guest2','ISOLATE'),('monitor2','RESTRICT'),('doctor3','RESTRICT'),('vendor_gw','RESTRICT')]:
            self.assertEqual(choose_source(topology,name),(name,kind))
            history=actions()
            for row in history:
                row['host']=name
                if row['action']=='ISOLATE':row['action']=kind
            self.assertEqual(assess(phases(),True,history,name,kind),'PASS')
            self.assertEqual(assess(phases(),True,history,'reception1','ISOLATE'),'FAIL')
        for name in ('ehr','unknown','reception1;echo bad'):
            with self.assertRaises(ValueError):choose_source(topology,name)
        self.assertEqual(assess(phases(),True,actions(),'monitor1','ISOLATE'),'FAIL')

    def test_random_excludes_previous_and_validate_does_not_write_history(self):
        topology=load_plan(ROOT/'configs/hospital.yaml')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'previous.json';path.write_text(json.dumps({'source_host':'guest1'}))
            with patch('scripts.demo.secrets.choice',side_effect=lambda values:values[0]) as choose:
                source,kind=choose_source(topology,'random',path)
                self.assertNotIn('guest1',choose.call_args.args[0])
                self.assertEqual(kind,'ISOLATE')
                self.assertNotEqual(source,'guest1')
                self.assertEqual(json.loads(path.read_text())['source_host'],'guest1')
        for name,kind in [('guest2','ISOLATE'),('pump2','RESTRICT')]:
            result=subprocess.run([sys.executable,'scripts/demo.py','--validate-only','--host='+name],cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['containment_action'],kind)
            self.assertEqual(json.loads(result.stdout)['source_host'],name)

    def test_cleanup_uses_only_created_container_id_and_stops_owned_processes(self):
        class Process:
            stopped=False
            def poll(self): return 0 if self.stopped else None
            def terminate(self): self.stopped=True
            def wait(self,timeout): return 0
        with tempfile.TemporaryDirectory() as tmp, patch('scripts.demo.ROOT',Path(tmp)):
            demo = Demo(True)
            p = Process()
            demo.processes.append(('test',p))
            with patch('scripts.demo.subprocess.Popen',return_value=p) as launch:
                demo.spawn([sys.executable,'-c','pass'],'dashboard')
                self.assertNotIn('HOSPITAL_ACTION_TOKEN',launch.call_args.kwargs['env'])
                self.assertNotIn('HOSPITAL_ENABLE_ACTIONS',launch.call_args.kwargs['env'])
            (demo.directory/'controller.cid').write_text('c'*64)
            with patch('scripts.demo.subprocess.run') as command:
                demo.stop()
                self.assertEqual(command.call_args.args[0],['docker','stop','--time','3','c'*64])
            self.assertTrue(p.stopped)
            # A malformed ID cannot be adopted or interpreted as a container name.
            (demo.directory/'controller.cid').write_text('somebody-elses-controller')
            with patch('scripts.demo.subprocess.run') as command:
                demo.stop()
                command.assert_not_called()
            self.assertNotIn(demo.environment['HOSPITAL_ACTION_TOKEN'],json.dumps({'run_id':demo.run_id}))


if __name__=='__main__':
    unittest.main()
