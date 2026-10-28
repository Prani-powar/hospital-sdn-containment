"""Persistent local lab. Run with sudo python3 scripts/lab.py; Ctrl+C cleans up."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
import argparse
import json
import queue
import re
import signal
import socket
import subprocess
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from scripts.demo import Demo, choose_source, read_controller, preflight
from topology.hospital import load_plan, run as run_network, require
from topology.critical_suite import CriticalSuite, load_config
from dashboard.serve import make_handler


class Controls:
    def __init__(self, hosts):
        self.hosts = hosts
        self.commands = queue.Queue(maxsize=1)
        self.lock = threading.Lock()
        self.updated_ns=time.monotonic_ns()
        self.status = {'phase':'starting', 'ready':False, 'host':None, 'events':[]}
    def update(self, **values):
        with self.lock:
            self.status.update(values); self.updated_ns=time.monotonic_ns()
    def event(self, text):
        with self.lock:
            self.status['events'] = (self.status['events'] + [{'timestamp_ns':time.monotonic_ns(), 'text':text}])[-40:]
    def snapshot(self):
        with self.lock:
            now=time.monotonic_ns()
            value=dict(self.status, timestamp_ns=self.updated_ns, eligible_hosts=self.hosts)
            value['ready']=value['ready'] and now-self.updated_ns<5_000_000_000
            proof=dict(value.get('containment') or {})
            proof['current']=bool(proof.get('current')) and 0<=now-proof.get('checked_ns',0)<3_500_000_000
            value['containment']=proof
            return value
    def submit(self, body):
        if not isinstance(body,dict) or set(body)!={'host'} or body['host'] not in self.hosts:
            raise ValueError('Choose an eligible configured endpoint')
        with self.lock:
            if not self.status['ready'] or time.monotonic_ns()-self.updated_ns>=5_000_000_000: raise ValueError('Wait for recovery and the next ready state')
            self.commands.put_nowait(body['host'])
            self.status['ready'] = False


def handler(controls):
    class Handler(make_handler(18080)):
        def lab_reply(self, code, value):
            raw=json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
        def local(self, mutation=False):
            origins={f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'}
            return ('http://'+self.headers.get('Host','') in origins and
                    (self.headers.get('Origin') in origins if mutation else self.headers.get('Origin') in origins|{None}))
        def do_GET(self):
            if self.path=='/api/lab':
                if not self.local(): self.send_error(403); return
                self.lab_reply(200,controls.snapshot()); return
            super().do_GET()
        def do_POST(self):
            if self.path!='/api/lab/scenario': return super().do_POST()
            if not self.local(True) or self.headers.get('Content-Type')!='application/json':
                self.send_error(403); return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=256: raise ValueError('Invalid command size')
                controls.submit(json.loads(self.rfile.read(size)))
                self.lab_reply(202,{'status':'queued'})
            except (ValueError,queue.Full) as exc: self.lab_reply(409,{'error':str(exc)})
    return Handler


def current_drop_proof(topology, host, kind, version):
    """Fresh exact namespace/version and source/destination drop readback on every switch."""
    from controller.enforcement import ACTION_PREFIX
    names=sorted(h['name'] for h in topology['hosts'])
    base=ACTION_PREFIX | ((names.index(host)+1)<<40) | (version<<16)
    address=next(h['ip'].split('/')[0] for h in topology['hosts'] if h['name']==host)
    fields=['nw_src','nw_dst'] if kind=='ISOLATE' else ['nw_src']
    for sw in topology['switches']:
        r=subprocess.run(['ovs-ofctl','-O','OpenFlow13','dump-flows',sw['name'],
                          f'cookie=0x{base:x}/0xffffffffffff0000'],capture_output=True,text=True,timeout=2)
        if r.returncode: return False
        for field in fields:
            if not any('priority=40000,' in line and ' actions=drop' in line and
                       re.search(r'(?:,| )'+field+'='+re.escape(address)+r'(?:,| )',line)
                       for line in r.stdout.splitlines()): return False
    return True


def confirmed_actions_since(actions, host, start_ns):
    """Pending/failed actions have a null timestamp; only confirmed integer times count."""
    return [r for r in actions if r.get('host') == host
            and r.get('status') == 'confirmed'
            and type(r.get('confirmed_ns')) is int
            and r['confirmed_ns'] >= start_ns]


class Lab(Demo):
    def exercise(self, net, suite):
        self.suite=suite
        self.phase='starting'
        self.wait(20,lambda: read_controller('/v1/health').get('status')=='ok' and
                  read_controller('/v1/actions').get('clinical_floor_confirmed') is True)
        self.epoch=read_controller('/v1/health')['controller_epoch']
        decision_command=[sys.executable,'-u','-m','decision.live','--continuous','--enforce',
                    '--run-id',self.run_id,'--output',str(self.directory/'decisions.jsonl'),
                    '--detector',getattr(self,'detector','M3')]
        if getattr(self,'model_directory',None):
            decision_command += ['--ml-model-directory',str(self.model_directory.resolve())]
        self.spawn(decision_command,'decision')
        self.controls=Controls([h['name'] for h in self.topology['hosts'] if h['role']!='critical_server'])
        self.controls.update(controller_epoch=self.epoch)
        self.server=ThreadingHTTPServer(('127.0.0.1',8088),handler(self.controls))
        self.server.daemon_threads=True
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        print('Persistent lab: http://127.0.0.1:8088 — select a source in Live lab session. Ctrl+C stops.',flush=True)
        generation=time.monotonic(); ready_after=generation+8
        active=None; number=0
        try:
            while True:
                self.wait(.3)
                now=time.monotonic()
                health=read_controller('/v1/health')
                require(health.get('controller_epoch')==self.epoch,'Controller restarted; stop and restart this session')
                # Renew finite workers while preserving network and detector ownership.
                if now-generation>85 and active is None:
                    self.controls.update(ready=False,phase='renewing clinical workers')
                    self.suite.stop()
                    self.suite=CriticalSuite(net,suite.config,ROOT/'artifacts'/'critical-suite',uuid.uuid4().hex)
                    self.suite.start(); generation=time.monotonic(); ready_after=generation+8
                    self.controls.event('Clinical workers renewed; waiting for fresh replies')
                for session in self.suite.sessions:
                    for name,p in session.processes:
                        require(p.poll() is None,f'Clinical worker {name} exited; inspect {session.directory}')
                status=read_controller('/v1/actions')
                actions=status.get('actions',[])
                decision=json.loads((ROOT/'artifacts'/'decision-status.json').read_text()) if (ROOT/'artifacts'/'decision-status.json').exists() else {}
                valid=(status.get('clinical_floor_confirmed') is True and health.get('status')=='ok' and decision.get('controller_epoch')==self.epoch and
                       0<=time.monotonic_ns()-decision.get('timestamp_ns',0)<5_000_000_000 and
                       decision.get('quality') not in ('unavailable','stopped') and not decision.get('mutation_halted',False))
                if active:
                    rows=confirmed_actions_since(actions,active['host'],active['start_ns'])
                    contained=next((r for r in rows if r.get('action')==active['kind']),None)
                    released=next((r for r in rows if r.get('action')=='RELEASE'),None)
                    if contained and not active.get('confirmed'):
                        active['confirmed']=True
                        self.controls.event('Switch readback confirmed '+active['kind']+' for '+active['host'])
                    if released and not active.get('released'):
                        active['released']=True
                        self.controls.event('Release confirmed; source remains suspicious until reviewed')
                    proof=False
                    if contained and not released and valid:
                        proof=current_drop_proof(self.topology,active['host'],active['kind'],contained['version'])
                    self.controls.update(containment={'host':active['host'],'kind':active['kind'],'current':proof,'checked_ns':time.monotonic_ns()})
                    self.controls.update(phase='recovered' if released else 'containment confirmed' if contained else 'observing fan-out')
                    if now-active['start']>65:
                        require(active.get('released'), 'No confirmed release within 65 seconds; inspect action/decision logs before another scenario')
                        require(active['process'].poll()==0,'Probe worker failed or did not finish')
                        self.controls.event('Scenario complete; ready for another device')
                        active=None; ready_after=now+5
                ready=active is None and valid and now>=ready_after and now-generation<85
                self.controls.update(ready=ready,phase=self.controls.snapshot()['phase'] if active else 'ready' if ready else 'warming / waiting for fresh evidence')
                try: source=self.controls.commands.get_nowait()
                except queue.Empty: continue
                require(ready,'Lab became unavailable before probe launch; restart after inspecting logs')
                source,kind=choose_source(self.topology,source)
                number+=1
                process=self.spawn([sys.executable,'-u','-m','controller.storm_probe','--host='+source,'--rate','4','--duration','16'],f'probe-{number}',net.get(source))
                active={'host':source,'kind':kind,'start':now,'start_ns':time.monotonic_ns(),'process':process}
                self.controls.update(ready=False,host=source,phase='observing fan-out')
                self.controls.event('Started harmless lab probes from '+source+' (4 packets/s for 16 seconds)')
        finally:
            self.controls.update(ready=False,phase='stopped')
            self.server.shutdown(); self.server.server_close()
            self.suite.stop()


def lab_preflight():
    import importlib.util
    require(sys.platform.startswith('linux') and __import__('os').geteuid()==0,
            'Run this launcher on Linux Mint with sudo /usr/bin/python3 scripts/lab.py')
    require(importlib.util.find_spec('mininet') is not None, 'Mininet missing from /usr/bin/python3; inspect the Mint Mininet installation')
    for port in (16653,18080,8088):
        with socket.socket() as reservation:
            reservation.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: reservation.bind(('127.0.0.1',port))
            except OSError as exc:
                raise RuntimeError(f'Port {port} unavailable: {exc}. Identify its owner with sudo ss -ltnp; stop only your previous lab service.') from exc
    r=subprocess.run(['docker','info'],capture_output=True,timeout=10)
    require(r.returncode==0,'Docker daemon unavailable; run sudo systemctl start docker and inspect its status')
    r=subprocess.run(['docker','image','inspect','hospital-controller:lab'],capture_output=True,timeout=8)
    require(r.returncode==0,'Image missing: sudo docker build -t hospital-controller:lab -f controller/Dockerfile .')
    artifacts=ROOT/'artifacts';artifacts.mkdir(exist_ok=True)
    probe=artifacts/('permission-check-'+uuid.uuid4().hex)
    try: probe.write_text('');probe.unlink()
    except PermissionError as exc: raise RuntimeError('Cannot write artifacts; inspect its ownership and filesystem permissions') from exc


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--validate-only',action='store_true')
    p.add_argument('--detector',choices=('M3','M1','M2'),default='M3')
    p.add_argument('--model-directory',type=Path,help='Trusted local calibrated ML artifacts')
    args=p.parse_args()
    if args.detector!='M3' and args.model_directory is None:
        p.error('M1/M2 requires --model-directory; no M3 fallback is used')
    topology=load_plan(ROOT/'configs/hospital.yaml'); suite=load_config(ROOT/'configs/critical-suite.yaml',topology)
    suite['duration_s']=180
    for s in suite['services']: s['duration_s']=180
    if args.validate_only:
        print(json.dumps({'hosts':len(topology['hosts']),'services':len(suite['services']),'persistent':True})); return 0
    lab=None
    try:
        lab_preflight()
        result=subprocess.run(['ovs-vsctl','--timeout=5','show'],capture_output=True,timeout=8)
        require(result.returncode==0,'Open vSwitch unavailable; inspect systemctl status openvswitch-switch')
        if args.model_directory:
            from decision.ml_scoring import MlScorer
            MlScorer.from_directory(args.model_directory)
        lab=Lab(True); lab.topology=topology
        lab.detector=args.detector;lab.model_directory=args.model_directory
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        lab.spawn(['docker','run','--rm','--network','host','--cidfile',str(lab.directory/'controller.cid'),
                   '--name','hospital-lab-'+lab.run_id[:12],'-e','HOSPITAL_ENABLE_ACTIONS','-e','HOSPITAL_ACTION_TOKEN','hospital-controller:lab'],'controller')
        def owned():
            try:
                h=read_controller('/v1/health')
                rows=(lab.directory/'controller.log').read_text().splitlines()
                epochs=[]
                for line in rows:
                    try:
                        r=json.loads(line)
                        if r.get('check')=='controller_started': epochs.append(r.get('epoch'))
                    except (ValueError,AttributeError): pass
                return h.get('controller_epoch') in epochs
            except (OSError,ValueError): return False
        lab.wait(20,owned)
        run_network(topology,False,critical_suite=suite,exercise=lab.exercise,experiment_run_id=lab.run_id)
    except KeyboardInterrupt: print('Lab stopped by user.',flush=True)
    except Exception as exc:
        print(json.dumps({'check':'persistent_lab_failed','error':str(exc),'logs':str(lab.directory) if lab else None}),flush=True); return 1
    finally:
        if lab:
            errors=lab.stop()
            if errors: print(json.dumps({'cleanup_errors':errors}))
    return 0
if __name__=='__main__': raise SystemExit(main())
