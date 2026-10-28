"""Generate explicit, archived 12/24/48 host configurations for research."""
from copy import deepcopy
from pathlib import Path
import yaml
from topology.hospital import load_plan


def prepare(root, output, count, window=5, threshold_scale=1, hysteresis=2, ablation="none"):
    if count not in (12,24,48) or window not in (2,5,10) or threshold_scale not in (.5,1,2) or hysteresis not in (1,2):
        raise ValueError('Unsupported experiment configuration')
    if ablation not in ('none','unprofiled'): raise ValueError('Unknown ablation')
    config = yaml.safe_load((root/'configs/hospital.yaml').read_text())
    if count == 12:
        keep = {'reception1','nurse1','ehr','pacs','lis','dns_ad','central_mon',
                'monitor1','pump1','imaging1','guest1','vendor_gw'}
        for segment in config['segments']:
            segment['hosts'] = [h for h in segment['hosts'] if h['name'] in keep]
    if count == 48:
        for i in range(24):
            segment = config['segments'][i % len(config['segments'])]
            role = segment['hosts'][0]['role']
            # Additional server-segment endpoints are ordinary admin workloads,
            # not invented critical-service sources.
            segment['hosts'].append({'name': f'extra{i+1}', 'role': 'admin' if role == 'critical_server' else role,
                                     'ip': f'10.20.0.{25+i}/24'})
    config['expected_host_count'] = count
    output.mkdir(parents=True, exist_ok=True)
    path = output/'hospital.yaml'; path.write_text(yaml.safe_dump(config, sort_keys=False))
    topology = load_plan(path)
    names = {h['name'] for h in topology['hosts']}
    paths = {'topology': path}
    for kind, filename in (('features','features.yaml'),('policy','detection.yaml')):
        c = deepcopy(yaml.safe_load((root/'configs'/filename).read_text()))
        for key in ('allowed_peers_by_role','allowed_peer_overrides'):
            c[key] = {k:[n for n in v if n in names] for k,v in c[key].items()
                      if key != 'allowed_peer_overrides' or k in names}
        if kind == 'features':
            c['window_s'] = window
            if ablation == 'unprofiled':
                c['allowed_peers_by_role'] = {role:[] for role in c['allowed_peers_by_role']}
                c['allowed_peer_overrides'] = {}
            c['summary_hosts'] = [h for h in c['summary_hosts'] if h in names]
        else:
            c['anomalous_windows'] = hysteresis
            c['protected_pairs'] = [p for p in c['protected_pairs'] if set(p) <= names]
            c['demo_hosts'] = [h for h in c['demo_hosts'] if h in names]
            for thresholds in c['thresholds'].values():
                for key in ('unique_dst','unique_dst_ports'):
                    thresholds[key] = max(1, round(thresholds[key]*threshold_scale))
                thresholds['unique_dst'] = min(count-1, thresholds['unique_dst'])
        paths[kind] = output/filename
        paths[kind].write_text(yaml.safe_dump(c, sort_keys=False))
    return topology, paths
