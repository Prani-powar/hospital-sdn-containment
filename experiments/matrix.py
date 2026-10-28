"""Plan or execute seed-separated benchmark matrices, sequentially and fail-fast."""
import argparse
import hashlib
import itertools
import json
import subprocess
import sys
from pathlib import Path


def cases(partition='validation', detectors=('M3',), scalability=False, sweeps=False):
    seeds = range(101,111) if partition=='validation' else range(201,211)
    for baseline, scenario, detector, seed in itertools.product(('B0','B1','B2','B3'), ('S1','S2','S3'), detectors, seeds):
        rates = (.5,1,2,4) if scenario=='S2' else (4,)
        for rate in rates:
            variants = [(24,5,1,2)]
            if scalability: variants += [(12,5,1,2),(48,5,1,2)]
            if sweeps:
                variants += [(24,w,t,h) for w,t,h in itertools.product((2,5,10),(.5,1,2),(1,2))
                             if (w,t,h)!=(5,1,2)]
            for hosts, window, scale, hysteresis in variants:
                for ablation in (('none','unprofiled') if sweeps else ('none',)):
                    yield dict(ablation=ablation,baseline=baseline,scenario=scenario,detector=detector,seed=seed,rate=rate,
                           hosts=hosts,window=window,threshold_scale=scale,hysteresis=hysteresis,
                           partition=partition)


def command(case, model_directory=None):
    argv=[sys.executable,'-m','experiments.run']
    for key,value in case.items(): argv += ['--'+key.replace('_','-'),str(value)]
    argv += ['--warmup',str(max(12,case['window']+3))]
    if case['detector']!='M3':
        if model_directory is None: raise ValueError('ML comparison requires --model-directory')
        argv += ['--model-directory',str(model_directory)]
    return argv


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition',choices=('validation','test'),default='validation')
    p.add_argument('--detectors',nargs='+',choices=('M3','M1','M2'),default=['M3'])
    p.add_argument('--scalability',action='store_true');p.add_argument('--sweeps',action='store_true')
    p.add_argument('--model-directory',type=Path)
    p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--execute',action='store_true')
    p.add_argument('--frozen-plan',type=Path,help='Required for test execution: validation-selected config manifest')
    args=p.parse_args()
    if args.partition=='test' and args.sweeps: p.error('Sweeps belong to validation seeds only')
    if args.execute and args.partition=='test' and not args.frozen_plan:
        p.error('Freeze selected validation configuration before held-out execution')
    selected=None
    if args.frozen_plan:
        selected=json.loads(args.frozen_plan.read_text())
        if set(selected) != {'window','threshold_scale','hysteresis'}:
            p.error('Frozen plan must contain window, threshold_scale, hysteresis only')
    plan=[]
    for case in cases(args.partition,tuple(args.detectors),args.scalability,args.sweeps):
        if selected: case.update(selected)
        plan.append(case)
    value={'schema_version':1,'cases':plan,'count':len(plan),'executed':False,
           'frozen_plan_sha256':hashlib.sha256(args.frozen_plan.read_bytes()).hexdigest() if args.frozen_plan else None}
    with args.plan.open('x') as stream: json.dump(value,stream,indent=2)
    print(json.dumps({'check':'experiment_matrix_written','runs':len(plan),'path':str(args.plan)}),flush=True)
    if args.execute:
        for case in plan:
            result=subprocess.run(command(case,args.model_directory))
            if result.returncode:
                print('Stopped on incomplete run; preserve its report and diagnose before continuing.',flush=True)
                return result.returncode
    return 0

if __name__=='__main__': raise SystemExit(main())
