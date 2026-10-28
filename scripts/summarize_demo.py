"""Reassess a finite demo report and export evidence tables without inventing results."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from scripts.demo import assess

PHASES = ('baseline','restricted','recovered')
VARIANT = 'synthetic-c1-c5-protected-floor-v1'
EVENT_FIELDS = {'run_id','timestamp_ns','stage','host','details'}
MAX_REPORT = 4*1024*1024


def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_REPORT+1)
    if len(raw)>MAX_REPORT:
        raise ValueError('Run report exceeds 4 MB')
    value = json.loads(raw,parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON value')))
    if not isinstance(value,dict):
        raise ValueError('Run report must be an object')
    return value,hashlib.sha256(raw).hexdigest()


def read_events(paths,run_id):
    """Bound audit input and reject mixed experiments or malformed Event objects."""
    if len(paths)>2:
        raise ValueError('At most two event files may be supplied')
    events = []
    for path in paths:
        path = Path(path)
        if path.stat().st_size>32*1024*1024:
            raise ValueError('Event file exceeds 32 MB')
        with path.open(encoding='utf-8') as stream:
            for index,line in enumerate(stream):
                if index>=20000 or len(line)>16384:
                    raise ValueError('Event input resource bound exceeded')
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row,dict) or row.get('run_id')!=run_id:
                    raise ValueError('Audit record belongs to a different or missing run')
                if row.get('check')=='live_run_metadata':
                    continue
                if (set(row)!=EVENT_FIELDS or type(row['timestamp_ns']) is not int
                        or row['timestamp_ns']<0 or not isinstance(row['details'],dict)
                        or not isinstance(row['stage'],str)):
                    raise ValueError('Malformed Event contract')
                events.append(row)
    return sorted(events,key=lambda e:e['timestamp_ns'])


def number(value):
    return type(value) in (int,float) and math.isfinite(value) and value>=0


def summarize(report,events=()):
    """Recompute outcomes. Export is an assessment of supplied evidence, not attestation."""
    if (report.get('check')!='hospital_demo_report' or report.get('schema_version')!=1
            or not isinstance(report.get('run_id'),str)
            or not re.fullmatch('[0-9a-f]{32}',report['run_id'])
            or report.get('mode') not in ('enforce','observe')
            or report.get('status') not in ('PASS','FAIL','OBSERVATION_ONLY')
            or not isinstance(report.get('phases'),dict)
            or set(report['phases'])-set(PHASES)
            or not isinstance(report.get('confirmed_actions'),list)
            or len(report['confirmed_actions'])>48):
        raise ValueError('Unsupported finite demo report')
    rows,notes = [],[]
    identity_ok = True
    coverage_ok = True
    for phase in PHASES:
        if phase not in report['phases']:
            continue
        p = report['phases'][phase]
        if (not isinstance(p,dict) or type(p.get('start_ns')) is not int
                or type(p.get('end_ns')) is not int or not 0<=p['start_ns']<p['end_ns']):
            raise ValueError('Invalid phase measurement interval')
        clinical = p.get('clinical',{})
        if not isinstance(clinical,dict) or not isinstance(clinical.get('services'),list):
            raise ValueError('Invalid clinical report')
        identity_ok = identity_ok and clinical.get('run_id')==report['run_id'] and clinical.get('variant')==VARIANT
        identity_ok = identity_ok and clinical.get('start_ns')==p['start_ns'] and clinical.get('end_ns')==p['end_ns']
        for service in clinical['services']:
            if not isinstance(service,dict) or service.get('flow_id') not in ('C1','C2','C3','C4','C5'):
                raise ValueError('Unknown critical service')
            sources = service.get('sources')
            if not isinstance(sources,list) or len(sources)>8:
                raise ValueError('Invalid source count')
            attempted = received = 0
            weighted_rtt = 0
            rtt_available = True
            for source in sources:
                if (not isinstance(source,dict) or type(source.get('attempted')) is not int
                        or type(source.get('received')) is not int
                        or not 0<=source['received']<=source['attempted']):
                    raise ValueError('Invalid probe counters')
                minimum = source.get('minimum_expected_probes')
                coverage_ok = coverage_ok and type(minimum) is int and minimum>0 and source['attempted']>=minimum
                attempted += source['attempted']
                received += source['received']
                if source['received']:
                    if number(source.get('mean_rtt_ms')):
                        weighted_rtt += source['mean_rtt_ms']*source['received']
                    else:
                        rtt_available = False
            rows.append({'phase':phase,'flow_id':service['flow_id'],'sources':len(sources),
                'attempted':attempted,'received':received,
                'success_rate':received/attempted if attempted else None,
                'mean_rtt_ms':weighted_rtt/received if received and rtt_available else None,
                'measurement_s':(p['end_ns']-p['start_ns'])/1e9})
    try:
        computed = assess(report['phases'],report['mode']=='enforce',report['confirmed_actions'],
                          report.get('source_host','reception1'),report.get('containment_action','ISOLATE'))
    except (ValueError,KeyError,TypeError,StopIteration,AttributeError):
        computed = 'FAIL'
        notes.append('Phase/action contract is incomplete or malformed.')
    probe = report.get('offered_probe')
    probe_ok = (isinstance(probe,dict) and probe.get('check')=='storm_probe_finished'
        and probe.get('host')==report.get('source_host','reception1') and type(probe.get('attempted')) is int and probe['attempted']>0
        and probe.get('send_errors')==0 and number(probe.get('elapsed_s')) and probe['elapsed_s']>0
        and number(probe.get('offered_packets_per_s'))
        and math.isclose(probe['offered_packets_per_s'],probe['attempted']/probe['elapsed_s'],rel_tol=.001))
    if not identity_ok:
        notes.append('Clinical run, variant or measurement intervals do not match this experiment.')
    if not coverage_ok:
        notes.append('Recorded minimum probe coverage is missing or was not reached.')
    if not probe_ok:
        notes.append('Completed error-free offered-load evidence is missing or inconsistent.')
    if report.get('error') or report.get('cleanup_errors'):
        notes.append('The original run recorded an execution or cleanup failure.')
    if not identity_ok or not coverage_ok or not probe_ok or report.get('error') or report.get('cleanup_errors'):
        computed = 'FAIL'
    if report['status']=='FAIL':
        # Never upgrade a failed run from its surviving partial evidence.
        computed = 'FAIL'
    timings = []
    for action in report['confirmed_actions']:
        if not isinstance(action,dict) or action.get('status')!='confirmed':
            continue
        proposal = action.get('proposal_id')
        requested = [e['timestamp_ns'] for e in events if e.get('run_id')==report['run_id']
                     and e.get('host')==action.get('host') and e.get('stage')=='rule_requested' and e.get('details',{}).get('proposal_id')==proposal]
        terminal_stage = 'released' if action.get('action')=='RELEASE' else 'rule_installed'
        installed = [e['timestamp_ns'] for e in events if e.get('run_id')==report['run_id']
                     and e.get('host')==action.get('host') and e.get('stage')==terminal_stage and e.get('details',{}).get('proposal_id')==proposal
                     and e.get('details',{}).get('readback_confirmed') is True]
        launched = [e['timestamp_ns'] for e in events if e.get('run_id')==report['run_id']
                    and e.get('stage')=='attack_start' and e.get('host')==action.get('host')
                    and e.get('details',{}).get('scope')=='owned_probe_process_launch']
        end = min(installed) if installed else None
        start = min(requested) if requested else None
        launch = min(launched) if launched else None
        timings.append({'proposal_id':proposal,'host':action.get('host'),'action':action.get('action'),
            'request_to_readback_s':(end-start)/1e9 if end is not None and start is not None and start<=end else None,
            'probe_launch_to_readback_s':(end-launch)/1e9 if end is not None and launch is not None and launch<=end else None})
    if not events:
        notes.append('No audit files supplied; stage timings remain unmeasured.')
    return {'source_host':report.get('source_host','reception1'),
        'containment_action':report.get('containment_action','ISOLATE'),
        'run_id':report['run_id'],'reported_status':report['status'],'evidence_status':computed,
        'consistent':report['status']==computed,'rows':rows,'action_timings':timings,
        'offered_probe':probe if probe_ok else None,'notes':notes,
        'scope':'Assessment of supplied run files; not independently verified',
        'latency_scope':'Process launch and rule readback only; not first/last malicious packet latency'}


def display(value):
    return 'unmeasured' if value is None else f'{value:.6f}' if isinstance(value,float) else str(value)


def markdown(summary):
    lines = ['# Hospital experiment results','',summary['scope'],'',
        f"Run: `{summary['run_id']}`",f"Reported outcome: **{summary['reported_status']}**",
        f"Reassessed outcome: **{summary['evidence_status']}**",'',
        f"Source: {summary['source_host']} · action: {summary['containment_action']}",'',
        'Counts below cover only the measured phase intervals, not the entire traffic session.','',
        '| Phase | Service | Sources | Attempted | Replies | Success rate | Mean RTT (ms) |',
        '|---|---|---:|---:|---:|---:|---:|']
    for row in summary['rows']:
        lines.append('| '+' | '.join(display(row[k]) for k in
            ('phase','flow_id','sources','attempted','received','success_rate','mean_rtt_ms'))+' |')
    lines += ['','## Action timing','',summary['latency_scope'],'',
        '| Host | Action | Request to readback (s) | Probe launch to readback (s) |',
        '|---|---|---:|---:|']
    for row in summary['action_timings']:
        # These fields are controller-supplied, so escape Markdown cell separators.
        cells=[display(row[k]).replace('|','/').replace('\n',' ') for k in
               ('host','action','request_to_readback_s','probe_launch_to_readback_s')]
        lines.append('| '+' | '.join(cells)+' |')
    if not summary['action_timings']:
        lines.append('| unmeasured | unmeasured | unmeasured | unmeasured |')
    if summary['notes']:
        lines += ['','## Evidence limits','']+['- '+n for n in summary['notes']]
    return '\n'.join(lines)+'\n'


def export(report_path,output_directory,event_paths=()):
    report,digest = read_json(report_path)
    events = read_events(event_paths,report.get('run_id'))
    summary = summarize(report,events)
    summary['report_sha256'] = digest
    directory = Path(output_directory)
    directory.mkdir(parents=True,exist_ok=False)
    (directory/'summary.json').write_text(json.dumps(summary,indent=2,allow_nan=False),encoding='utf-8')
    (directory/'summary.md').write_text(markdown(summary),encoding='utf-8')
    with (directory/'clinical.csv').open('w',newline='',encoding='utf-8') as stream:
        fields=['phase','flow_id','sources','attempted','received','success_rate','mean_rtt_ms','measurement_s']
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(summary['rows'])
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--events',type=Path,nargs='*',default=[])
    args=parser.parse_args()
    try:
        result=export(args.input,args.output_directory,args.events)
        print(json.dumps({'check':'demo_evidence_exported','evidence_status':result['evidence_status'],
            'consistent':result['consistent'],'directory':str(args.output_directory)}))
        return 0 if result['consistent'] else 2
    except (ValueError,TypeError,KeyError,OSError) as exc:
        print(json.dumps({'check':'demo_export_failed','error':str(exc)[:256]}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
