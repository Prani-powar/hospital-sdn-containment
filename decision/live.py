"""Finite single-owner live pipeline. Observe by default; explicit opt-in for writes."""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
import json
import os
import re
from pathlib import Path
import time
import uuid

from controller.action_client import ActionBusy, ControllerClient
from controller.telemetry_client import TelemetryClient
from decision.collect_features import event
from decision.detection import from_config
from decision.features import from_files

ROOT = Path(__file__).resolve().parents[1]


def bind_detector(engine, detector, scorer=None):
    """Select one decision source; never silently fall back from ML to M3."""
    if detector not in ('M1', 'M2', 'M3'):
        raise ValueError('Choose detector M1, M2 or M3')
    if detector != 'M3':
        if scorer is None:
            raise ValueError('M1/M2 enforcement requires --ml-model-directory')
        def selected(feature):
            scores = scorer.score(feature)
            prefix = detector.lower()
            anomalous = scores[prefix + '_anomalous']
            value = scores['m1_raw_anomaly_score'] if detector == 'M1' else scores['m2_attack_probability']
            return {'host': feature['host'], 'anomaly_score': value,
                    'anomalous': anomalous,
                    'model_version': detector + ':' + scores['model_artifact_created_at']}
        engine.score_provider = selected
    else:
        engine.score_provider = None
    engine.detector = detector



class LivePipeline:
    """Bounded outbox; actual confirmation is separate from desired policy state.

    No blind POST retries: ambiguity, epoch changes, rejection or failure stop all
    subsequent writes in this run. A busy 409 is safe to retry because the actor
    explicitly did not reserve the proposal. Contained windows are censored, so
    they cannot drive clean release or vendor escalation in this first variant.
    """
    def __init__(self, engine, client, enforce=False, clock=time.monotonic_ns, run_id=None, ml_scorer=None):
        self.engine, self.client, self.enforce, self.clock = engine, client, enforce, clock
        self.run_id = run_id or uuid.uuid4().hex
        if not isinstance(self.run_id,str) or not re.fullmatch('[0-9a-f]{32}',self.run_id):
            raise ValueError('Run id must contain exactly 32 lowercase hex characters')
        self.epoch = None
        self.queue = deque(maxlen=24)
        self.pending = None
        self.halted = None
        self.latest = {}
        self.observed = {}
        self.events = deque(maxlen=256)
        self.event_seq = 0
        self.actor_seq = 0
        self.actor_ready = False
        self.quality = 'starting'
        self.ml_scorer = ml_scorer

    def emit(self, stage, host, details):
        self.event_seq += 1
        row = {'seq': self.event_seq, 'event': event(self.run_id, stage, host, details)}
        self.events.append(row)
        return row

    def halt(self, reason):
        self.halted = reason
        self.queue.clear()

    def propose(self, proposal):
        proposal = dict(proposal, run_id=self.run_id)
        self.emit('decision', proposal['action']['host'], {'proposal': proposal, 'mode': 'live',
                  'applied': False})
        if self.enforce and not self.halted:
            if len(self.queue) == self.queue.maxlen:
                self.halt('Outbox capacity exceeded; reconciliation required')
            else:
                self.queue.append(proposal)

    def ingest(self, result, epoch):
        if self.epoch is not None and epoch != self.epoch:
            self.engine.invalidate()
            self.halt('Controller restarted; reconciliation required before further writes')
            self.observed.clear()
        self.epoch = epoch
        self.quality = result['status']
        if result['status'] != 'ready':
            self.engine.invalidate()
        for proposal in self.engine.tick(self.clock()):
            self.propose(proposal)
        for feature in result['features']:
            name = feature['host']
            # Drop rules suppress PacketIns. Neither clean windows nor persistent
            # vendor evidence can be inferred from the remaining allowed traffic.
            self.emit('features_ready', name, {'window_end_ns': feature['timestamp_ns'],
                      'window_s': feature['window_s'], 'feature': feature, 'quality': result['quality']})
            censored = self.engine.states[name].action is not None
            if censored:
                self.engine.invalidate(name)
            scored = ({'status': 'censored', 'score': None,
                       'desired_state': self.engine.states[name].status, 'proposals': []}
                      if censored else self.engine.consume(feature, result['quality'], self.clock(), epoch))
            try:
                ml_scores = self.ml_scorer.score(feature) if self.ml_scorer else None
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                # An incompatible trained artefact is an observable data-quality
                # fault, never a reason to fall back to an action-changing score.
                ml_scores = {"status": "unavailable", "reason": str(exc)[:160]}
            previous_streak = self.latest.get(name, {}).get('detection', {}).get('anomalous_streak', 0)
            if (not censored and scored['status'] in ('scored','needs_source_attribution_or_human_review')
                    and scored['score'] and scored['score']['anomalous']
                    and self.engine.states[name].anomalous_streak >= self.engine.config['anomalous_windows']
                    and previous_streak < self.engine.config['anomalous_windows']):
                self.emit('detector_triggered', name, {'score': scored['score'],
                          'window_end_ns': feature['timestamp_ns']})
            self.latest[name] = {'feature': feature, 'score': scored['score'],
                'desired_state': scored.get('desired_state', 'UNKNOWN'),
                'evidence_censored': censored, 'status': scored['status'], 'score_error': scored.get('reason'),
                'detection': {'thresholds': dict(self.engine.config['thresholds'][feature['role']]),
                              'anomalous_streak': self.engine.states[name].anomalous_streak}}
            if ml_scores is not None:
                self.latest[name]['ml_scores'] = ml_scores
            if scored['score'] is not None:
                self.emit('scored', name, {'score': scored['score'], 'evidence_censored': censored})
            for proposal in scored['proposals']:
                self.propose(proposal)

    async def reconcile(self):
        if not self.enforce or self.halted:
            return
        try:
            status = await self.client.get_actions()
            if status.get('controller_epoch') != self.epoch:
                self.halt('Action endpoint controller epoch differs from telemetry')
                return
            self.actor_ready = status.get('clinical_floor_confirmed') is True
            actions = status.get('actions', [])
            known = {p['proposal_id'] for p in self.queue}
            if self.pending:
                known.add(self.pending['proposal_id'])
            # Fresh finite runs do not take over a previous planner's leases.
            if any(a.get('proposal_id') not in known and a.get('host') not in self.observed for a in actions):
                self.halt('Existing planner actions found; actual-rule reconciliation required')
                return
            self.observed = {a['host']: a for a in actions}
            for row in status.get('events', []):
                if row['seq'] > self.actor_seq:
                    if row['seq'] != self.actor_seq + 1:
                        self.halt('Controller action event gap; audit reconciliation required')
                    self.actor_seq = row['seq']
                    self.event_seq += 1
                    self.events.append({'seq': self.event_seq, 'event': row['event']})
            if self.pending:
                current = self.observed.get(self.pending['action']['host'])
                if current and current['proposal_id'] == self.pending['proposal_id']:
                    if current['status'] == 'failed':
                        self.halt('Switch action failed: ' + str(current.get('error', ''))[:160])
                    elif current['status'] == 'confirmed':
                        self.pending = None
                if self.pending and self.clock() - self.pending_since > 20_000_000_000:
                    self.halt('Action confirmation deadline exceeded; no automatic retry')
                return
            if self.queue and self.actor_ready:
                proposal = self.queue[0]
                # Never install an old quarantine after its desired lease elapsed.
                if proposal['action']['action'] != 'RELEASE' and self.clock() >= (
                        proposal['created_ns'] + proposal['action']['timeout_s'] * 1_000_000_000):
                    self.queue.popleft()
                    return
                method = self.client.remove_rule if proposal['action']['action'] == 'RELEASE' else self.client.push_rule
                response = await method(proposal)
                if response.get('proposal_id') != proposal['proposal_id']:
                    self.halt('Action acceptance identity mismatch')
                    return
                self.pending = self.queue.popleft()
                self.pending_since = self.clock()
        except ActionBusy:
            pass
        except Exception as exc:
            self.halt('Action boundary uncertain; no retry: ' + str(exc)[:160])

    def snapshot(self):
        return {'schema_version': 1, 'run_id': self.run_id, 'timestamp_ns': self.clock(),
                'controller_epoch': self.epoch, 'mode': 'enforce' if self.enforce else 'observe',
                'quality': self.quality, 'mutation_halted': self.halted,
                'clinical_floor_confirmed': self.actor_ready,
                'detector': getattr(self.engine, 'detector', 'M3'),
                'detection_policy': {'anomalous_windows': self.engine.config['anomalous_windows'],
                    'max_feature_age_s': self.engine.config['max_feature_age_s'],
                    'thresholds': self.engine.config['thresholds']},
                'hosts': self.latest, 'actions': list(self.observed.values()),
                'pending': self.pending['proposal_id'] if self.pending else None,
                'outbox_depth': len(self.queue), 'events': list(self.events),
                'release_policy': 'TTL reconciliation; censored clean windows never release'}


def write_snapshot(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, allow_nan=False), encoding='utf-8')
    temporary.replace(path)


async def run(args):
    engine = from_config(args.topology, args.policy)
    extractor = from_files(args.topology, args.features)
    token = os.environ.get('HOSPITAL_ACTION_TOKEN', '')
    if args.enforce and not token:
        raise ValueError('Enforcement requires HOSPITAL_ACTION_TOKEN in the service environment')
    client = ControllerClient(token, args.base_url) if args.enforce else TelemetryClient(args.base_url, concurrency=1)
    model_directory = getattr(args, 'ml_model_directory', None)
    scorer = None
    if model_directory:
        try:
            from decision.ml_scoring import MlScorer
        except ImportError as exc:
            raise ValueError('Optional ML packages missing; install infra/requirements/services.txt only when using --ml-model-directory') from exc
        scorer = MlScorer.from_directory(model_directory)
    bind_detector(engine, getattr(args, 'detector', 'M3'), scorer)
    pipeline = LivePipeline(engine, client, args.enforce, run_id=getattr(args,'run_id',None), ml_scorer=scorer)
    output = args.output or ROOT/'artifacts'/'decisions'/f'{pipeline.run_id}.jsonl'
    output.parent.mkdir(parents=True, exist_ok=True)
    last_seq = 0
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps({'check': 'live_run_metadata', 'run_id': pipeline.run_id,
            'mode': 'enforce' if args.enforce else 'observe', 'model_version': engine.config['model_version'], 'detector': engine.detector,
            'synthetic_critical_service_variant': 'synthetic-c1-c5-protected-floor-v1'})+'\n')
        for index in __import__("itertools").count() if getattr(args,"continuous",False) else range(args.samples):
            started = time.monotonic()
            try:
                body = await client.get_stats(require_complete=False)
                pipeline.emit('poll_received', None, {'controller_epoch': body.get('controller_epoch'),
                              'controller_snapshot_ns': body.get('timestamp_ns')})
                result = extractor.ingest(body, time.monotonic_ns())
                pipeline.ingest(result, body.get('controller_epoch'))
                await pipeline.reconcile()
            except Exception as exc:
                extractor.invalidate('http_read_failed')
                engine.invalidate()
                pipeline.quality = 'unavailable'
                pipeline.emit('poll_received', None, {'error': str(exc)[:160]})
                # No automatic containment decision from stale data.
            snapshot = pipeline.snapshot()
            write_snapshot(args.status, snapshot)
            rows = [row for row in pipeline.events if row['seq'] > last_seq]
            if rows and last_seq and rows[0]['seq'] != last_seq+1:
                raise RuntimeError('Local audit ring overflow')
            for row in rows:
                stream.write(json.dumps(row['event'], allow_nan=False)+'\n')
                last_seq = row['seq']
            stream.flush()
            if getattr(args,"continuous",False) or index+1 < args.samples:
                await asyncio.sleep(max(0, extractor.config['poll_interval_s']-(time.monotonic()-started)))
        pipeline.quality = 'stopped'
        write_snapshot(args.status, pipeline.snapshot())
    print(json.dumps({'check': 'live_run_stopped', 'run_id': pipeline.run_id,
                      'mode': snapshot['mode'], 'mutation_halted': pipeline.halted, 'output': str(output)}))
    return 1 if pipeline.halted else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enforce', action='store_true')
    parser.add_argument('--continuous', action='store_true', help='Keep one planner owner until interrupted')
    parser.add_argument('--run-id', help='Optional shared 32-hex experiment identifier')
    parser.add_argument('--samples', type=int, default=600)
    parser.add_argument('--topology', type=Path, default=ROOT/'configs'/'hospital.yaml')
    parser.add_argument('--features', type=Path, default=ROOT/'configs'/'features.yaml')
    parser.add_argument('--policy', type=Path, default=ROOT/'configs'/'detection.yaml')
    parser.add_argument('--base-url', default='http://127.0.0.1:18080')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--status', type=Path, default=ROOT/'artifacts'/'decision-status.json')
    parser.add_argument('--detector', choices=('M3','M1','M2'), default='M3',
                        help='Detector driving the same validated containment policy')
    parser.add_argument('--ml-model-directory', type=Path,
                        help='Trusted local output directory from decision.ml_pipeline; required for M1/M2; M3 can display observational ML scores')
    args = parser.parse_args()
    if not 2 <= args.samples <= 3600:
        parser.error('Use 2..3600 samples')
    try:
        return asyncio.run(run(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({'check': 'live_run_failed', 'error': str(exc)[:256]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
