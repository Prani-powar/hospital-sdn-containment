"""Aggregate all valid research records, including misses and clinical failures."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from scripts.aggregate_benchmarks import mean_ci

FACTORS=('partition','baseline','scenario','detector','hosts','rate','window','threshold_scale','hysteresis','ablation')


def aggregate(reports):
    groups=defaultdict(list); seen=set(); incomplete=[]
    for r in reports:
        if r.get('schema_version')!=2 or r.get('instrumentation_status')!='COMPLETE' or r.get('error') or r.get('cleanup_errors'):
            incomplete.append(r.get('run_id'));continue
        key=tuple(r[k] for k in FACTORS)
        identity=key+(r['seed'],)
        if identity in seen: raise ValueError('Duplicate experimental cell and seed')
        seen.add(identity); groups[key].append(r)
    rows=[]
    for key,runs in sorted(groups.items()):
        metrics={}
        for name in ('detection_delay_s','enforcement_delay_s','time_to_contain_s',
                     'critical_flow_success_rate','hosts_infected_before_containment','false_isolation_rate'):
            values=[r['metrics'][name] for r in runs if r['metrics'].get(name) is not None]
            metrics[name]={**(mean_ci(values) if values else {'n':0,'mean':None,'ci95_half_width':None}),
                           'missing':len(runs)-len(values)}
        rows.append(dict(zip(FACTORS,key),runs=len(runs),seeds=sorted(r['seed'] for r in runs),
                         ten_seeds_complete=len(runs)>=10,metrics=metrics,
                         containment_observed=sum(r['metrics']['containment_observed'] for r in runs)))
    return {'schema_version':2,'groups':rows,'incomplete_runs':incomplete,
            'note':'Latency means condition on observed events; misses reported separately. Failures of protection are retained.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path('artifacts/demo'));p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    reports=[json.loads(p.read_text()) for p in args.root.glob('*/research-report.json')]
    if not reports: p.error('No measured research reports found')
    with args.output.open('x') as stream: json.dump(aggregate(reports),stream,indent=2,allow_nan=False)

if __name__=='__main__': main()
