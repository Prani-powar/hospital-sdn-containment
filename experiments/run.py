"""One finite, owned Linux experiment; raw failures are retained, never relabelled successes."""
import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path

import yaml

from experiments.baselines import OwnedRules, blind_rules, static_rules
from experiments.configuration import prepare
from experiments.metrics import summarize
from scripts.demo import Demo, ROOT, read_controller
from scripts.lab import lab_preflight
from topology.critical_suite import load_config
from topology.hospital import load_plan, require, run as run_network


def read_jsonl(path):
    if not path.exists(): return []
    rows = []
    for line in path.read_text().splitlines(keepends=True):
        if not line.endswith('\n'): continue
        try: rows.append(json.loads(line))
        except ValueError: raise ValueError(f'Incomplete or invalid audit file: {path}')
    return rows


class Experiment(Demo):
    def __init__(self, args):
        super().__init__(args.baseline == 'B3')
        self.args = args
        self.rules = None
        self.report = None
        self.environment.update(OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
        self.events = []

    def exercise(self, net, suite):
        self.suite = suite
        self.phase = 'readiness'
        def ready():
            health = read_controller('/v1/health')
            require(health.get('controller_epoch') == self.epoch, 'Controller restarted during experiment')
            return health.get('status') == 'ok' and (not self.enforce or
                    read_controller('/v1/actions').get('clinical_floor_confirmed') is True)
        self.wait(30, ready)
        self.rules = OwnedRules(self.run_id, [s['name'] for s in self.topology['switches']])
        if self.args.baseline == 'B1':
            self.rules.install(static_rules(self.topology, suite.config['services']))
        argv = [sys.executable, '-u', '-m', 'decision.live', '--continuous',
                '--run-id', self.run_id, '--topology', str(self.paths['topology']),
                '--features', str(self.paths['features']), '--policy', str(self.paths['policy']),
                '--detector', self.args.detector, '--output', str(self.directory/'decisions.jsonl'),
                '--status', str(self.directory/'decision-status.json')]
        if self.enforce: argv += ['--enforce']
        if self.args.model_directory: argv += ['--ml-model-directory', str(self.args.model_directory.resolve())]
        self.spawn(argv, 'decision')
        processes = []
        duration = self.args.warmup + self.args.duration + 4
        source = 'vendor_gw' if self.args.scenario == 'S3' else 'reception1'
        for host in self.topology['hosts']:
            name = host['name']
            processes.append(self.spawn([sys.executable, '-u', '-m', 'experiments.agents',
                '--topology', str(self.paths['topology']), '--host', name, '--source', source,
                '--run-id', self.run_id, '--seed', str(self.args.seed), '--scenario', self.args.scenario,
                '--rate', str(self.args.rate), '--duration', str(duration),
                '--attack-after', str(self.args.warmup), '--output', str(self.directory/f'agent-{name}.jsonl')],
                'agent-'+name, net.get(name)))
        warmup_start = time.monotonic_ns()
        self.wait(self.args.warmup)
        self.measure_start = time.monotonic_ns()
        self.phase = 'measurement'
        installed = set()
        fault_injected = False
        seen = 0
        last_sample = 0
        finish = time.monotonic() + self.args.duration
        samples = (self.directory/'samples.jsonl').open('x')
        try:
            while time.monotonic() < finish:
                if self.args.fault and not fault_injected and time.monotonic_ns()-self.measure_start >= 10_000_000_000:
                    from experiments.faults import inject
                    stamp=time.monotonic_ns()
                    inject(self, self.args.fault)
                    fault_injected=True
                    (self.directory/'fault.json').write_text(json.dumps({'fault':self.args.fault,'injected_ns':stamp}))
                self.wait(.25)
                require(all(p.poll() is None for p in processes), 'An agent exited before measurement finished')
                require(all(p.poll() is None for session in suite.sessions for _, p in session.processes),
                        'A clinical worker exited before measurement finished')
                require(ready(), 'Controller/switch health degraded during measurement')
                path = self.directory/'decision-status.json'
                require(path.exists(), 'Decision snapshot missing after warm-up')
                snap = json.loads(path.read_text())
                require(0 <= time.monotonic_ns()-snap['timestamp_ns'] < 5_000_000_000,
                        'Decision snapshot stale')
                require(not snap.get('mutation_halted'), 'Decision actor halted: '+str(snap.get('mutation_halted')))
                # JSONL can be observed while a line is being written; consume only
                # complete newline-terminated records, and retry the final fragment.
                audit_path = self.directory/'decisions.jsonl'
                lines = audit_path.read_text().splitlines(keepends=True)
                complete = [json.loads(line) for line in lines if line.endswith('\n')]
                for event in complete[seen:]:
                    if event.get('stage') == 'detector_triggered' and self.args.baseline == 'B2':
                        host = event['host']
                        if host in installed: continue
                        records = self.rules.install(blind_rules(self.topology, host, self.args.duration+2))
                        self.events.append(dict(run_id=self.run_id, timestamp_ns=time.monotonic_ns(),
                            stage='experiment_isolation_confirmed', host=host,
                            details={'readback_confirmed': True, 'rules': records, 'baseline': 'B2'}))
                        installed.add(host)
                seen = len(complete)
                now = time.monotonic_ns()
                if now-last_sample >= 1_000_000_000:
                    from controller.telemetry_client import request_json
                    _, stats=request_json('http://127.0.0.1:18080','/v1/stats')
                    samples.write(json.dumps({'timestamp_ns': now, 'clinical': suite.summary(max(self.measure_start,now-3_000_000_000),now),
                                              'health': read_controller('/v1/health'),
                                              'telemetry_complete': stats.get('complete'),
                                              'reported_rule_rows':sum(len((s.get('snapshot') or {}).get('rows',[])) for s in stats.get('switches',[]))})+'\n')
                    samples.flush()
                    last_sample=now
            end = time.monotonic_ns()
            # Leave one probe timeout for the last sent requests to be logged.
            self.wait(.2)
            clinical = suite.summary(self.measure_start, end)
            # Keep the attack boundary from all agents, including the few ms of
            # stagger between first agent activation and measurement start.
            rows = [r for path in self.directory.glob('agent-*.jsonl') for r in read_jsonl(path)]
            rows += [r for r in read_jsonl(self.directory/'decisions.jsonl') if 'stage' in r] + self.events
            inventory = {h['name']:h for h in self.topology['hosts']}
            metrics = summarize(rows, clinical, warmup_start, end, inventory)
            from experiments.metrics import resources
            metrics.update(resources(read_jsonl(self.directory/'samples.jsonl')))
            instrumentation_ok = (all(any(r['stage']=='agent_ready' and r['host']==h for r in rows) for h in inventory)
                and metrics['source_host'] is not None and metrics['critical_attempted'] > 0
                and all(v['attempted'] >= v['minimum_expected_probes'] and v['invalid_records']==0
                        for s in clinical['services'] for v in s['sources']))
            self.report = {'schema_version':2, 'run_id':self.run_id, 'baseline':self.args.baseline,
                'scenario':self.args.scenario, 'detector':self.args.detector, 'seed':self.args.seed,
                'partition': self.args.partition, 'hosts':len(inventory), 'rate':self.args.rate,
                'window':self.args.window, 'threshold_scale':self.args.threshold_scale,
                'hysteresis':self.args.hysteresis, 'ablation':self.args.ablation, 'controller_epoch':self.epoch,
                'warmup_start_ns':warmup_start, 'measurement_start_ns':self.measure_start, 'end_ns':end,
                'instrumentation_status':'COMPLETE' if instrumentation_ok else 'INCOMPLETE',
                'metrics':metrics, 'clinical':clinical,
                'limits':'Synthetic marker spread only; no exploit, clinical semantics or production safety claim.'}
            (self.directory/'ground-truth.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows
                if r['stage'] in ('infection_marker','marker_received','attack_send')))
            (self.directory/'baseline-events.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in self.events))
            features = [dict(check='feature_window', run_id=self.run_id,
                            feature=r['details']['feature'],quality=r['details']['quality'])
                        for r in rows if r['stage']=='features_ready' and 'feature' in r['details']]
            (self.directory/'features.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in features))
        finally:
            samples.close()
            self.rules.cleanup()
            self.rules = None


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', choices=('B0','B1','B2','B3'), default='B3')
    p.add_argument('--scenario', choices=('S1','S2','S3'), default='S1')
    p.add_argument('--detector', choices=('M3','M1','M2'), default='M3')
    p.add_argument('--seed',type=int,default=101)
    p.add_argument('--partition',choices=('validation','test'),default='validation')
    p.add_argument('--hosts',type=int,choices=(12,24,48),default=24)
    p.add_argument('--rate',type=float,default=4,help='S2 sweep: .5, 1, 2, 4 packets/s per infected agent')
    p.add_argument('--window',type=int,choices=(2,5,10),default=5)
    p.add_argument('--threshold-scale',type=float,choices=(.5,1,2),default=1)
    p.add_argument('--ablation',choices=('none','unprofiled'),default='none')
    p.add_argument('--hysteresis',type=int,choices=(1,2),default=2)
    p.add_argument('--warmup',type=int,default=12)
    p.add_argument('--duration',type=int,default=40)
    p.add_argument('--controller-cpu',type=int)
    p.add_argument('--workload-cpu',type=int)
    p.add_argument('--model-directory',type=Path)
    p.add_argument('--fault', choices=('decision-stop','controller-restart','switch-disconnect'))
    p.add_argument('--validate-only',action='store_true')
    return p


def main():
    args = parser().parse_args()
    require(0 < args.rate <= 20 and 10 <= args.duration <= 90 and
            args.window+3 <= args.warmup <= 30, 'Invalid rate, warm-up or duration')
    require(args.seed in (range(101,111) if args.partition=='validation' else range(201,211)),
            'Validation seeds are 101..110; held-out test seeds are 201..210')
    require(args.detector=='M3' or args.model_directory is not None, 'M1/M2 requires a trusted trained model directory')
    if args.detector != 'M3' and args.partition == 'test':
        metadata=json.loads((args.model_directory/'metrics.json').read_text())
        require(metadata.get('split',{}).get('validation_runs') and metadata.get('fit_seeds')
                and metadata.get('calibration_seeds')
                and set(metadata['fit_seeds']+metadata['calibration_seeds']) <= set(range(101,111)),
                'Held-out ML runs require validation-calibrated artifacts fitted only on seeds 101..110')
    if args.validate_only:
        print(json.dumps(dict(check='research_plan_valid', **{k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},
                              network_started=False))); return 0
    experiment = None
    old_affinity = None
    error = None
    try:
        lab_preflight()
        allowed = sorted(os.sched_getaffinity(0))
        require(len(allowed)>=2, 'Timing experiments require two available CPUs')
        controller_cpu = args.controller_cpu if args.controller_cpu is not None else allowed[0]
        workload_cpu = args.workload_cpu if args.workload_cpu is not None else allowed[1]
        require(controller_cpu in allowed and workload_cpu in allowed and controller_cpu!=workload_cpu,
                'Choose two distinct allowed CPUs')
        old_affinity = set(allowed)
        os.sched_setaffinity(0,{workload_cpu})
        experiment = Experiment(args)
        experiment.topology, experiment.paths = prepare(ROOT,experiment.directory/'config', args.hosts,
                                                        args.window,args.threshold_scale,args.hysteresis,args.ablation)
        suite = load_config(ROOT/'configs/critical-suite.yaml',load_plan(ROOT/'configs/hospital.yaml'))
        names = {h['name'] for h in experiment.topology['hosts']}
        floor = yaml.safe_load((ROOT/'configs/enforcement.yaml').read_text())
        if args.hosts == 12:
            floor['variant'] = 'synthetic-c1-c5-scaled-research-v1'
        for service in floor['critical_services']:
            service['sources'] = [h for h in service['sources'] if h in names]
        (experiment.directory/'config/enforcement.yaml').write_text(yaml.safe_dump(floor))
        for service in suite['services']:
            service['sources'] = [h for h in service['sources'] if h in names]
            service['duration_s'] = 160
        suite['duration_s'] = 160
        suite['variant'] = floor['variant']
        metadata = dict(clock='time.monotonic_ns/CLOCK_MONOTONIC',boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            clock_resolution_s=time.get_clock_info('monotonic').resolution,
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                           for folder in ('controller','decision','topology','experiments') for p in (ROOT/folder).glob('*.py')},
            platform=platform.platform(),python=sys.version,controller_cpu=controller_cpu,workload_cpu=workload_cpu,
            ovs_affinity='Existing OVS daemon affinity unchanged; record as timing limitation',
            configs={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (experiment.directory/'config').glob('*.yaml')})
        for name, command in [('docker',['docker','version']),('ovs',['ovs-vsctl','--version']),
                              ('packages',[sys.executable,'-m','pip','freeze']),
                              ('controller_image',['docker','image','inspect','--format','{{.Id}}','hospital-controller:lab'])]:
            r = subprocess.run(command,capture_output=True,text=True,timeout=15)
            metadata[name] = {'exit':r.returncode,'output':r.stdout,'stderr':r.stderr}
        (experiment.directory/'environment.json').write_text(json.dumps(metadata,indent=2))
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        config_path = str((experiment.directory/'config').resolve())
        docker = ['docker','run','--rm','--network','host','--cpuset-cpus',str(controller_cpu),
                  '--cidfile',str(experiment.directory/'controller.cid'),'--name','hospital-research-'+experiment.run_id[:12],
                  '-v',config_path+':/experiment:ro','-e','HOSPITAL_TOPOLOGY_CONFIG=/experiment/hospital.yaml',
                  '-e','HOSPITAL_POLICY_CONFIG=/experiment/detection.yaml',
                  '-e','HOSPITAL_ENFORCEMENT_CONFIG=/experiment/enforcement.yaml',
                  '-e','HOSPITAL_ENABLE_ACTIONS','-e','HOSPITAL_ACTION_TOKEN','hospital-controller:lab']
        experiment.spawn(docker,'controller')
        def owned():
            try:
                health=read_controller('/v1/health')
                for line in (experiment.directory/'controller.log').read_text().splitlines():
                    try: row=json.loads(line)
                    except ValueError: continue
                    if row.get('check')=='controller_started' and row.get('epoch')==health.get('controller_epoch'):
                        experiment.epoch=row['epoch']; return True
                return False
            except (OSError,ValueError): return False
        experiment.wait(20,owned)
        run_network(experiment.topology,False,critical_suite=suite,exercise=experiment.exercise,
                    experiment_run_id=experiment.run_id)
    except (Exception,KeyboardInterrupt) as exc:
        error = str(exc) or 'Interrupted'
        if experiment and (experiment.directory/'fault.json').exists():
            from experiments.faults import classify
            fault=json.loads((experiment.directory/'fault.json').read_text())
            fault.update(observed_error=error,halt_observed=classify(fault['fault'],error),observed_ns=time.monotonic_ns())
            (experiment.directory/'fault.json').write_text(json.dumps(fault,indent=2))
    finally:
        if experiment:
            cleanup_errors = experiment.stop()
            result = experiment.report or {'schema_version':2,'run_id':experiment.run_id,
                'baseline':args.baseline,'scenario':args.scenario,'seed':args.seed,'detector':args.detector,
                'instrumentation_status':'INCOMPLETE'}
            result.update(error=error,cleanup_errors=cleanup_errors)
            (experiment.directory/'research-report.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
            print(json.dumps({'check':'research_run_finished','report':str(experiment.directory/'research-report.json'),
                              'error':error,'instrumentation_status':result['instrumentation_status']}))
        else:
            print(json.dumps({'check':'research_preflight_failed','error':error}))
        if old_affinity is not None: os.sched_setaffinity(0,old_affinity)
    return 0 if experiment and experiment.report and not error and not cleanup_errors and experiment.report['instrumentation_status']=='COMPLETE' else 1

if __name__=='__main__':
    raise SystemExit(main())
