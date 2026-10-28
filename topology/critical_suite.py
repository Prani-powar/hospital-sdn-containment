"""Bounded C1–C5 synthetic service workers and evidence reports, never medical data."""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
from pathlib import Path
import time
import uuid

import yaml

try:
    from .clinical import ClinicalTraffic
    from .hospital import UniqueKeyLoader, load_plan, require
except ImportError:
    from clinical import ClinicalTraffic
    from hospital import UniqueKeyLoader, load_plan, require

ROOT = Path(__file__).resolve().parents[1]
# Support direct-script invocation from the repository root as well as -m.
if not __package__:
    import sys
    sys.path.insert(0, str(ROOT))


def load_config(path: Path, topology: dict) -> dict:
    """Use exactly the named enforcement floor's endpoints and ports."""
    from controller.core import Fabric
    from controller.enforcement import load_enforcement
    require(path.stat().st_size <= 100_000, 'Critical suite config exceeds 100 KB')
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(c, dict) and set(c) == {'schema_version','variant','rate_hz',
        'duration_s','startup_timeout_s','reply_timeout_s'}, 'Critical suite contract mismatch')
    require(c['schema_version'] == 1, 'Unsupported critical suite schema')
    floor = load_enforcement(ROOT/'configs/enforcement.yaml', Fabric(topology))
    require(c['variant'] == floor['variant'], 'Critical suite and floor variants differ')
    for key, low, high in [('rate_hz',1,10),('duration_s',10,180),('startup_timeout_s',1,10)]:
        require(type(c[key]) is int and low <= c[key] <= high, f'Invalid {key}')
    require(type(c['reply_timeout_s']) in (int,float) and math.isfinite(c['reply_timeout_s'])
            and 0 < c['reply_timeout_s'] < 1/c['rate_hz'], 'Invalid reply timeout')
    hosts = {h['name']: h for h in topology['hosts']}
    services = []
    for i, service in enumerate(floor['critical_services'], 1):
        services.append({'schema_version':1, 'flow_id':f'C{i}',
            'server':service['server'], 'sources':list(service['sources']),
            'server_ip':str(ipaddress.IPv4Interface(hosts[service['server']]['ip']).ip),
            'udp_port':service['port'], **{k:c[k] for k in
                ('rate_hz','duration_s','startup_timeout_s','reply_timeout_s')}})
    return dict(c, services=services)


class CriticalSuite:
    """One owner for 18 bounded worker processes; cleanup survives partial startup."""
    def __init__(self, net, config, root, run_id=None):
        self.config, self.net = config, net
        self.run_id = run_id or uuid.uuid4().hex
        require(isinstance(self.run_id,str) and re.fullmatch('[0-9a-f]{32}',self.run_id), 'Invalid suite run id')
        self.directory = Path(root).resolve()/self.run_id
        self.sessions = []

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        (self.directory/'suite.json').write_text(json.dumps({
            'run_id':self.run_id, 'variant':self.config['variant'],
            'services':self.config['services']}, indent=2))
        for service in self.config['services']:
            session = ClinicalTraffic(self.net, service, self.directory/service['flow_id'])
            session.run_id = self.run_id
            self.sessions.append(session)
            session.start()

    def stop(self):
        errors = []
        for session in reversed(self.sessions):
            try:
                session.stop()
            except Exception as exc:
                errors.append(str(exc)[:160])
        if errors:
            raise RuntimeError('Critical worker cleanup failed: '+'; '.join(errors))

    def summary(self, start_ns: int, end_ns: int) -> dict:
        """Only exact run/flow/source records inside this interval count as evidence."""
        require(type(start_ns) is int and type(end_ns) is int and 0 <= start_ns < end_ns,
                'Invalid measurement interval')
        result = {'check':'critical_suite_status', 'run_id':self.run_id,
            'variant':self.config['variant'], 'start_ns':start_ns, 'end_ns':end_ns,
            'timestamp_ns':time.monotonic_ns(), 'services':[], 'status':'unmeasured'}
        all_ok = True
        for session in self.sessions:
            c = session.config
            sources = []
            for source in c['sources']:
                path = session.directory/f'{source}.jsonl'
                rows = read_probes(path, self.run_id, c['flow_id'], source, start_ns, end_ns)
                records = rows['records']
                attempted = len(records)
                good = [r['rtt_ms'] for r in records if r['success']]
                duration = (end_ns-start_ns)/1e9
                minimum = max(1, math.floor(duration*c['rate_hz']*.5))
                valid = rows['invalid_records'] == 0 and attempted >= minimum
                ok = valid and len(good) == attempted
                all_ok = all_ok and ok
                sources.append({'source':source, 'attempted':attempted, 'received':len(good),
                    'success_rate':len(good)/attempted if attempted else None,
                    'mean_rtt_ms':sum(good)/len(good) if good else None,
                    'p95_rtt_ms':sorted(good)[math.ceil(.95*len(good))-1] if good else None,
                    'minimum_expected_probes':minimum, 'invalid_records':rows['invalid_records'],
                    'status':'PASS' if ok else 'FAIL' if attempted else 'unmeasured'})
            result['services'].append({'flow_id':c['flow_id'],'server':c['server'],
                'udp_port':c['udp_port'], 'sources':sources})
        if len(self.sessions) == 5:
            result['status'] = 'PASS' if all_ok else 'FAIL'
        return result


def read_probes(path, run_id, flow_id, source, start_ns, end_ns):
    """Bound log input, reject duplicates and malformed data instead of claiming success."""
    if not path.exists():
        return {'records':[], 'invalid_records':0}
    try:
        require(path.stat().st_size <= 8*1024*1024, 'Clinical log exceeds 8 MB')
        lines = path.read_text(encoding='utf-8').splitlines()
    except (OSError, ValueError):
        return {'records':[], 'invalid_records':0}
    records, invalid, sequences = [], 0, set()
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            invalid += 1
            continue
        if not isinstance(row,dict):
            invalid += 1
            continue
        if row.get('check') != flow_id.lower()+'_probe':
            continue
        stamp = row.get('timestamp_ns')
        if type(stamp) is not int:
            invalid += 1
            continue
        if not start_ns <= stamp <= end_ns:
            continue
        if (row.get('run_id') != run_id or row.get('source') != source
                or type(row.get('seq')) is not int or row['seq'] < 1 or row['seq'] in sequences
                or type(row.get('success')) is not bool
                or row['success'] and (type(row.get('rtt_ms')) not in (int,float)
                    or not math.isfinite(row['rtt_ms']) or row['rtt_ms'] < 0)):
            invalid += 1
            continue
        sequences.add(row['seq'])
        records.append(row)
    return {'records':records, 'invalid_records':invalid}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,default=ROOT/'configs/critical-suite.yaml')
    p.add_argument('--topology',type=Path,default=ROOT/'configs/hospital.yaml')
    args = p.parse_args()
    try:
        print(json.dumps(load_config(args.config, load_plan(args.topology)), indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'check':'critical_suite_config_error','error':str(exc)[:160]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
