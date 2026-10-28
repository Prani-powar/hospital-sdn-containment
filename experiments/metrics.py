"""Conservative metrics from one boot's monotonic event stream; null means unmeasured."""


def latencies(attack_ns, decision_ns, confirmed_ns):
    for value in (attack_ns, decision_ns, confirmed_ns):
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError('Invalid monotonic timestamp')
    if decision_ns is not None and (attack_ns is None or decision_ns < attack_ns):
        return dict(detection_delay_s=None, enforcement_delay_s=None, time_to_contain_s=None)
    if confirmed_ns is not None and (decision_ns is None or confirmed_ns < decision_ns):
        raise ValueError('Confirmation predates decision')
    return {'detection_delay_s': (decision_ns-attack_ns)/1e9 if decision_ns is not None else None,
            'enforcement_delay_s': (confirmed_ns-decision_ns)/1e9 if confirmed_ns is not None else None,
            'time_to_contain_s': (confirmed_ns-attack_ns)/1e9 if confirmed_ns is not None else None}


def summarize(events, clinical, start_ns, end_ns, inventory):
    """Measure seed-source latency and all-host false isolation; retain misses."""
    events = sorted(events, key=lambda r: r['timestamp_ns'])
    infected, first_send, decisions, confirmed = {}, {}, {}, {}
    for row in events:
        host, stamp, stage = row.get('host'), row['timestamp_ns'], row['stage']
        if not start_ns <= stamp <= end_ns:
            continue
        if stage == 'infection_marker': infected.setdefault(host, stamp)
        if stage == 'attack_send': first_send.setdefault(host, stamp)
        if stage == 'detector_triggered':
            decisions.setdefault(host, stamp)
        if stage == 'experiment_isolation_confirmed': confirmed.setdefault(host, stamp)
        if stage == 'rule_installed' and row.get('details', {}).get('action') != 'RELEASE':
            confirmed.setdefault(host, stamp)
    sources = [r['host'] for r in events if r['stage'] == 'infection_marker'
               and r.get('details', {}).get('source') == 'scenario_seed']
    source = sources[0] if sources else None
    attack = first_send.get(source)
    decision = decisions.get(source)
    confirmation = confirmed.get(source)
    result = latencies(attack, decision, confirmation)
    result['containment_observed'] = confirmation is not None
    result['hosts_infected_before_containment'] = sum(t <= (confirmation or end_ns) for t in infected.values())
    false = [h for h, t in confirmed.items() if h not in infected or infected[h] > t]
    result['false_isolation_hosts'] = sorted(false)
    result['false_isolation_rate'] = len(false) / len(inventory)
    detected=set(decisions)
    true_detected={h for h in detected if h in infected and decisions[h]>=infected[h]}
    precision=len(true_detected)/len(detected) if detected else None
    recall=len(true_detected)/len(infected) if infected else None
    result['host_detection_precision']=precision
    result['host_detection_recall']=recall
    result['host_detection_f1']=(2*precision*recall/(precision+recall)
                                 if precision is not None and recall is not None and precision+recall else None)
    result['infected_hosts'] = sorted(infected)
    result['source_host'] = source
    attempted = received = invalid = 0
    for service in clinical.get('services', []):
        for row in service.get('sources', []):
            attempted += row.get('attempted', 0)
            received += row.get('received', 0)
            invalid += row.get('invalid_records', 0)
    result['critical_flow_success_rate'] = received/attempted if attempted and not invalid else None
    result['critical_attempted'], result['critical_received'] = attempted, received
    result['false_isolation_critical'] = any(inventory[h]['role'] in ('clinical','iomt','critical_server') for h in false)
    return result


def resources(samples):
    health=[s['health'] for s in samples if 'health' in s]
    cpu=None
    if len(health)>1 and len({r['controller_epoch'] for r in health})==1:
        elapsed=(health[-1]['timestamp_ns']-health[0]['timestamp_ns'])/1e9
        if elapsed>0:
            cpu=100*(health[-1]['process_cpu_s']-health[0]['process_cpu_s'])/elapsed
    return {'controller_cpu_one_core_percent':cpu,
            'controller_peak_rss_mb':max((r['process_max_rss_bytes']/1024**2 for r in health),default=None),
            'peak_reported_rule_rows':max((s['reported_rule_rows'] for s in samples),default=None),
            'complete_telemetry_samples':sum(s.get('telemetry_complete') is True for s in samples),
            'telemetry_samples':len(samples)}
