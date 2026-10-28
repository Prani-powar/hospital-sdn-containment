"""Finite owned lab demonstration. --validate-only needs no Docker, root or Mininet."""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decision.live import write_snapshot
from topology.critical_suite import load_config
from topology.hospital import load_plan, require, run as run_network


def read_controller(endpoint):
    require(endpoint in ('/v1/health','/v1/actions'), 'Unknown demo endpoint')
    connection = http.client.HTTPConnection('127.0.0.1',18080,timeout=2)
    try:
        connection.request('GET',endpoint)
        response = connection.getresponse()
        raw = response.read(4*1024*1024+1)
        require(response.status in (200,503) and len(raw)<=4*1024*1024, 'Invalid controller response')
        body = json.loads(raw)
        require(isinstance(body,dict), 'Controller response must be an object')
        return body
    finally:
        connection.close()


def assess(phases, enforce, action_history, source_host="reception1", containment_action="ISOLATE"):
    """Only measured clinical probes, ping exits and confirmed action IDs can pass."""
    try:
        expected_source, expected_action = choose_source(load_plan(ROOT/'configs/hospital.yaml'),source_host)
        if expected_source!=source_host or expected_action!=containment_action:
            return 'FAIL'
    except (ValueError,KeyError,TypeError):
        return 'FAIL'
    required = ('baseline','restricted','recovered') if enforce else ('baseline','recovered')
    if any(name not in phases for name in required):
        return 'FAIL'
    expected = {'C1':{'monitor1','monitor2','monitor3'},'C2':{'pump1','pump2'},
                'C3':{'imaging1'},'C4':{'nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'},
                'C5':{'lis'}}
    for name in required:
        phase = phases[name]
        report = phase.get('clinical',{})
        services = report.get('services',[])
        if (report.get('status') != 'PASS' or len(services)!=5
                or {v.get('flow_id') for v in services}!={'C1','C2','C3','C4','C5'}):
            return 'FAIL'
        for service in services:
            rows = service.get('sources',[])
            if {v.get('source') for v in rows} != expected[service['flow_id']] or len(rows) != len(expected[service['flow_id']]):
                return 'FAIL'
            for row in rows:
                if (type(row.get('attempted')) is not int or row['attempted']<1
                        or row.get('received')!=row['attempted'] or row.get('invalid_records')!=0
                        or row.get('status')!='PASS'):
                    return 'FAIL'
        if not phase.get('ping',{}).get('executed'):

            return 'FAIL'
        code = phase['ping'].get('exit_code')
        if code != (1 if name=='restricted' else 0):
            return 'FAIL'
    if not enforce:
        return 'OBSERVATION_ONLY'
    for kind in (containment_action,'RELEASE'):
        if not any(v.get('action')==kind and v.get('host')==source_host
                   and v.get('status')=='confirmed' and type(v.get('confirmed_ns')) is int
                   and v['confirmed_ns']>0 and re.fullmatch('[0-9a-f]{64}',v.get('proposal_id',''))
                   for v in action_history):
            return 'FAIL'
    isolate = next(v for v in action_history if v.get('action')==containment_action and v.get('host')==source_host)
    release = next(v for v in action_history if v.get('action')=='RELEASE' and v.get('host')==source_host)
    if (isolate['proposal_id']==release['proposal_id']
            or not phases['baseline']['end_ns'] <= isolate['confirmed_ns'] <= phases['restricted']['start_ns']
            or not phases['restricted']['end_ns'] <= release['confirmed_ns'] <= phases['recovered']['start_ns']):
        return 'FAIL'
    return 'PASS'


class Demo:
    def __init__(self, enforce, source_host="reception1", containment_action="ISOLATE"):
        self.source_host = source_host
        self.containment_action = containment_action
        self.enforce = enforce
        self.run_id = uuid.uuid4().hex
        self.directory = ROOT/'artifacts'/'demo'/self.run_id
        self.directory.mkdir(parents=True,exist_ok=False)
        self.environment = dict(os.environ, LC_ALL='C', HOSPITAL_ENABLE_ACTIONS='1' if enforce else '0',
                                HOSPITAL_ACTION_TOKEN=secrets.token_hex(32))
        self.processes, self.streams = [], []
        self.phases, self.action_history = {}, []
        self.probe = None
        self.epoch = None
        self.suite = None
        self.phase = 'starting'
        self.started_ns = time.monotonic_ns()
        self.last_clinical = 0

    def spawn(self, args, name, host=None):
        stream = (self.directory/(name+'.log')).open('x')
        self.streams.append(stream)
        method = host.popen if host is not None else subprocess.Popen
        environment = dict(self.environment)
        if name not in ('controller','decision'):
            for key in ('HOSPITAL_ACTION_TOKEN','HOSPITAL_ENABLE_ACTIONS'):
                environment.pop(key,None)
        process = method(args,cwd=ROOT,env=environment,stdout=stream,stderr=stream)
        self.processes.append((name,process))
        return process

    def clinical_status(self):
        if self.suite is None:
            return
        now = time.monotonic_ns()
        if now-self.last_clinical < 1_000_000_000:
            return
        self.last_clinical = now
        try:
            summary = self.suite.summary(max(self.started_ns,now-3_000_000_000),now)
            write_snapshot(ROOT/'artifacts'/'critical-status.json',{
                'schema_version':1,'controller_epoch':self.epoch,'timestamp_ns':now,
                'phase':self.phase,'stopped':False,'measurement':summary})
        except OSError:
            pass

    def wait(self, seconds, condition=None):
        deadline = time.monotonic()+seconds
        while time.monotonic()<deadline:
            for name, process in self.processes:
                if name in ('controller','decision','dashboard') and process.poll() is not None:
                    raise RuntimeError(f'{name} exited unexpectedly; see owned run logs')
            self.clinical_status()
            if condition is not None:
                value = condition()
                if value:
                    return value
            time.sleep(.25)
        if condition is not None:
            raise TimeoutError('Demo phase deadline exceeded: '+self.phase)

    def ping(self, net):
        target = next(h['ip'].split('/')[0] for h in self.topology['hosts'] if h['name']=='ehr')
        process = net.get(self.source_host).popen(['ping','-n','-c','2','-W','1',target],
                                             stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        try:
            raw,_ = process.communicate(timeout=5)
        except BaseException:
            process.kill()
            process.wait(timeout=2)
            raise
        text = raw.decode(errors='replace') if isinstance(raw,bytes) else raw
        # Exit 1 alone is insufficient: the actual ping summary must show loss.
        expected = '100% packet loss' if self.phase=='restricted' else '0% packet loss'
        executed = ('2 packets transmitted' in text and expected in text
                    and (self.phase=='restricted' or '100% packet loss' not in text))
        return {'executed':executed,'exit_code':process.returncode,'output':text[:16384]}

    def record_phase(self, net):
        start = time.monotonic_ns()
        self.wait(3)
        ping = self.ping(net)
        end = time.monotonic_ns()
        self.phases[self.phase] = {'start_ns':start,'end_ns':end,
            'clinical':self.suite.summary(start,end),'ping':ping}
        print(json.dumps({'check':'demo_phase','phase':self.phase,
            'clinical_status':self.phases[self.phase]['clinical']['status'],
            'ping_exit_code':ping['exit_code']}),flush=True)

    def action(self, kind):
        try:
            status = read_controller('/v1/actions')
        except (OSError, http.client.HTTPException):
            return None
        require(status.get('controller_epoch')==self.epoch, 'Controller epoch changed during demonstration')
        for row in status.get('actions',[]):
            if row.get('host')==self.source_host and row.get('action')==kind and row.get('status')=='confirmed':
                if row['proposal_id'] not in {v['proposal_id'] for v in self.action_history}:
                    self.action_history.append(row)
                return row
        return None

    def exercise(self, net, suite):
        self.suite = suite
        self.phase = 'controller_ready'
        def ready():
            health = read_controller('/v1/health')
            self.epoch = health.get('controller_epoch')
            if health.get('status')!='ok':
                return False
            return not self.enforce or read_controller('/v1/actions').get('clinical_floor_confirmed') is True
        self.wait(20,ready)
        self.spawn([sys.executable,'-u','-m','decision.live','--samples','120',
                    '--run-id',self.run_id,'--output',str(self.directory/'decisions.jsonl')]+(['--enforce'] if self.enforce else []),'decision')
        self.spawn([sys.executable,'-u','dashboard/serve.py'],'dashboard')
        print('Local dashboard: http://127.0.0.1:8088 — finite demo only',flush=True)
        self.phase = 'baseline'
        self.wait(6)
        self.record_phase(net)
        self.phase = 'fanout'
        process = self.spawn([sys.executable,'-u','-m','controller.storm_probe','--host='+self.source_host,
                    '--rate','4','--duration','16'],'fanout',net.get(self.source_host))
        # This timestamp is observed process launch, not a fabricated first packet.
        with (self.directory/'events.jsonl').open('x') as stream:
            stream.write(json.dumps({'run_id':self.run_id,'timestamp_ns':time.monotonic_ns(),
                'stage':'attack_start','host':self.source_host,'details':{'scope':'owned_probe_process_launch',
                'pid':process.pid,'rate_pps':4,'duration_s':16}})+'\n')
        if self.enforce:
            self.wait(22,lambda:self.action(self.containment_action))
            self.phase = 'restricted'
            self.record_phase(net)
            self.phase = 'awaiting_release'
            self.wait(35,lambda:self.action('RELEASE'))
        else:
            self.wait(17)
        self.phase = 'recovered'
        self.record_phase(net)
        require(process.wait(timeout=3)==0, 'Owned fan-out worker failed')
        rows = (self.directory/'fanout.log').read_text().splitlines()
        for line in rows:
            try:
                row = json.loads(line)
                if isinstance(row,dict) and row.get('check')=='storm_probe_finished':
                    self.probe = row
            except ValueError:
                continue
        require(self.probe and self.probe.get('host')==self.source_host
                and type(self.probe.get('attempted')) is int and self.probe['attempted']>0
                and self.probe.get('send_errors')==0,
                'No completed error-free offered-load evidence from the owned worker')

    def stop(self):
        errors = []
        # The Docker ID file is created by this run. Never stop a name we did not create.
        cidfile = self.directory/'controller.cid'
        if cidfile.exists():
            cid = cidfile.read_text().strip()
            if re.fullmatch('[0-9a-f]{64}',cid):
                try:
                    result = subprocess.run(['docker','stop','--time','3',cid],capture_output=True,timeout=8)
                    if result.returncode!=0 and any(name=='controller' and p.poll() is None for name,p in self.processes):
                        errors.append('Owned container stop did not succeed; inspect the run logs')
                except (OSError,subprocess.TimeoutExpired) as exc:
                    errors.append(str(exc)[:160])
        for name,process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        for stream in self.streams:
            stream.close()
        for filename in ('critical-status.json','decision-status.json'):
            path = ROOT/'artifacts'/filename
            if path.exists():
                try:
                    value = json.loads(path.read_text())
                    if value.get('controller_epoch')==self.epoch:
                        value.update(stopped=True,quality='stopped',timestamp_ns=time.monotonic_ns())
                        write_snapshot(path,value)
                except (OSError,ValueError):
                    pass
        return errors


def preflight():
    require(sys.platform.startswith('linux') and hasattr(os,'geteuid') and os.geteuid()==0,
            'The real lab demo requires Linux and sudo; --validate-only works without them')
    for port in (16653,18080,8088):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',port))
    result = subprocess.run(['docker','image','inspect','hospital-controller:lab'],
                            capture_output=True,timeout=8)
    require(result.returncode==0,'Build hospital-controller:lab first; this runner does not install or build software')


def choose_source(topology, requested, previous_path=None):
    """Select only configured, automatically containable lab endpoints.

    Critical servers need separately attributed-source protection, not isolation.
    Random selection uses office/guest endpoints whose ISOLATE case is comparable.
    Explicit medical/clinical/vendor sources use RESTRICT and retain clinical allows.
    """
    hosts = {h['name']:h for h in topology['hosts']}
    if requested == 'random':
        previous = None
        path = previous_path or ROOT/'artifacts'/'last-demo-source.json'
        try:
            previous = json.loads(path.read_text())['source_host']
        except (OSError,ValueError,KeyError,TypeError):
            pass
        choices = [name for name,h in hosts.items()
                   if h['role'] in ('admin','guest') and name != previous]
        requested = secrets.choice(choices)
    require(requested in hosts, 'Choose a configured hospital host')
    role = hosts[requested]['role']
    require(role != 'critical_server',
            'Critical servers require attributed-source protection; choose an endpoint for this live demo')
    action = 'ISOLATE' if role in ('admin','guest') else 'RESTRICT'
    return requested, action


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enforce',action='store_true',help='Explicitly enable real timed containment in the lab')
    parser.add_argument('--validate-only',action='store_true')
    parser.add_argument('--host',default='random',help='Lab source host, or random (excludes the previous random source)')
    args = parser.parse_args()
    topology = load_plan(ROOT/'configs/hospital.yaml')
    suite = load_config(ROOT/'configs/critical-suite.yaml',topology)
    source_host, containment_action = choose_source(topology,args.host)
    if args.validate_only:
        print(json.dumps({'check':'demo_plan_valid','mode':'enforce' if args.enforce else 'observe',
            'hosts':len(topology['hosts']),'services':len(suite['services']),
            'sources':sum(len(v['sources']) for v in suite['services']),
            'worker_processes':sum(1+len(v['sources']) for v in suite['services']),
            'source_host':source_host,'containment_action':containment_action,
            'fanout_rate_pps':4,'fanout_duration_s':16,'network_started':False},indent=2))
        return 0
    demo = None
    error = None
    try:
        preflight()
        demo = Demo(args.enforce,source_host,containment_action)
        write_snapshot(ROOT/'artifacts'/'last-demo-source.json',{'source_host':source_host})
        print(json.dumps({'check':'demo_source_selected','source_host':source_host,
                          'containment_action':containment_action,'scope':'harmless_lab_probe'}),flush=True)
        demo.topology = topology
        def terminate(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM,terminate)
        demo.spawn(['docker','run','--rm','--network','host','--cidfile',str(demo.directory/'controller.cid'),
            '--name','hospital-demo-'+demo.run_id[:12],'-e','HOSPITAL_ENABLE_ACTIONS',
            '-e','HOSPITAL_ACTION_TOKEN','hospital-controller:lab'],'controller')
        demo.phase = 'controller_startup'
        def listening():
            try:
                health = read_controller('/v1/health')
                # Verify that the listener belongs to our own newly-created container.
                rows = (demo.directory/'controller.log').read_text().splitlines()
                epochs = []
                for line in rows:
                    try:
                        row = json.loads(line)
                        if isinstance(row,dict) and row.get('check')=='controller_started':
                            epochs.append(row.get('epoch'))
                    except ValueError:
                        continue
                return health if health.get('controller_epoch') in epochs else False
            except (OSError,ValueError):
                return False
        demo.wait(15,listening)
        run_network(topology,False,critical_suite=suite,exercise=demo.exercise,experiment_run_id=demo.run_id)
    except (Exception,KeyboardInterrupt) as exc:
        error = str(exc)[:256] or 'Interrupted'
    finally:
        if demo:
            cleanup_errors = demo.stop()
            report = {'check':'hospital_demo_report','schema_version':1,'run_id':demo.run_id,
                'source_host':demo.source_host,'containment_action':demo.containment_action,
                'controller_epoch':demo.epoch,'mode':'enforce' if args.enforce else 'observe',
                'status':assess(demo.phases,args.enforce,demo.action_history,demo.source_host,demo.containment_action) if not error and not cleanup_errors else 'FAIL',
                'error':error,'cleanup_errors':cleanup_errors,'phases':demo.phases,
                'confirmed_actions':demo.action_history,'offered_probe':demo.probe,'timestamp_ns':time.monotonic_ns(),
                'synthetic_services':True,'scope':'actual_lab_run_not_production_safety'}
            write_snapshot(demo.directory/'report.json',report)
            try:
                from scripts.summarize_demo import export
                audit = [p for p in (demo.directory/'events.jsonl',demo.directory/'decisions.jsonl') if p.exists()]
                summary = export(demo.directory/'report.json',demo.directory/'summary',audit)
                print(json.dumps({'check':'demo_summary_written','evidence_status':summary['evidence_status'],
                                  'consistent':summary['consistent']}),flush=True)
            except (OSError,ValueError,TypeError,KeyError) as exc:
                # Keep the original measurement report even if its optional audit
                # or presentation export is incomplete; never invent timing data.
                print(json.dumps({'check':'demo_summary_failed','error':str(exc)[:256]}),flush=True)
            print(json.dumps({'check':'hospital_demo_finished','status':report['status'],
                              'report':str(demo.directory/'report.json')}),flush=True)
            return 0 if report['status'] in ('PASS','OBSERVATION_ONLY') else 1
    print(json.dumps({'check':'demo_preflight_failed','error':error}),flush=True)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
