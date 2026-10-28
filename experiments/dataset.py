"""Build documented, boundary-censored labels from controlled research runs only."""
import argparse
import json
from pathlib import Path
from experiments.run import read_jsonl


def label(features, truth, decisions, start_ns, end_ns):
    infections={}
    censored={}
    for r in truth:
        if r['stage']=='infection_marker':
            infections[r['host']]=min(infections.get(r['host'],r['timestamp_ns']),r['timestamp_ns'])
    for r in decisions:
        if r.get('stage') in ('rule_installed','experiment_isolation_confirmed'):
            censored[r['host']]=min(censored.get(r['host'],r['timestamp_ns']),r['timestamp_ns'])
    result=[]
    for r in features:
        f=r['feature']; end=f['timestamp_ns']; start=end-round(f['window_s']*1e9); host=f['host']
        if start < start_ns or end > end_ns or r['quality'].get('valid') is not True: continue
        if host in censored and end >= censored[host]: continue
        infection=infections.get(host)
        if infection is not None and start < infection <= end: continue
        target='attack' if infection is not None and start >= infection else 'normal'
        result.append(dict(r,label=target,label_provenance='in_memory_marker_receipt_whole_window'))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    report=json.loads((args.run/'research-report.json').read_text())
    if report['instrumentation_status']!='COMPLETE' or report.get('error'):
        p.error('Controlled complete instrumentation required')
    # Warm-up is clean by construction, but its initial incomplete windows are
    # still rejected by the collector. Keep those clean windows for training.
    rows=label(read_jsonl(args.run/'features.jsonl'),read_jsonl(args.run/'ground-truth.jsonl'),
               read_jsonl(args.run/'decisions.jsonl')+read_jsonl(args.run/'baseline-events.jsonl'),
               report['warmup_start_ns'],report['end_ns'])
    with args.output.open('x') as stream:
        for r in rows: stream.write(json.dumps(dict(r,seed=report['seed'],partition=report['partition']))+'\n')
    print(json.dumps({'labelled_windows':len(rows),'output':str(args.output)}))

if __name__=='__main__':main()
