"""Live pipeline tests with real detector and fake action transport, no OVS claim."""
import asyncio
import copy
from pathlib import Path
import tempfile
import unittest

from controller.action_client import ActionBusy
from decision.detection import from_config
from decision.live import LivePipeline, write_snapshot
from decision.replay_detection import demo_records

ROOT = Path(__file__).resolve().parents[2]


class Client:
    def __init__(self):
        self.sent = []
        self.status = {'controller_epoch': 'epoch', 'clinical_floor_confirmed': True,
                       'actions': [], 'events': []}
        self.error = None

    async def get_actions(self):
        return copy.deepcopy(self.status)

    async def push_rule(self, proposal):
        if self.error:
            raise self.error
        self.sent.append(proposal)
        self.status['actions'] = [{'host': proposal['action']['host'],
            'proposal_id': proposal['proposal_id'], 'action': proposal['action']['action'], 'status': 'pending'}]
        return self.status['actions'][0]

    remove_rule = push_rule


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.engine = from_config(ROOT/'configs/hospital.yaml', ROOT/'configs/detection.yaml')
        self.client = Client()
        self.now = 1_000_000_000
        self.pipeline = LivePipeline(self.engine, self.client, True, lambda: self.now)
        self.fixture = next(r for r in demo_records(self.engine)
                            if r.get('feature', {}).get('host') == 'reception1')

    def ingest(self, name='reception1', suspect=True):
        f = copy.deepcopy(self.fixture['feature'])
        f.update(timestamp_ns=self.now, host=name, role=self.engine.fabric.hosts[name]['role'])
        if not suspect:
            f.update(unique_dst=1, unique_dst_ports=1, off_allow_list_flows=0, new_peers=1)
        self.pipeline.ingest({'status': 'ready', 'features': [f],
                              'quality': self.fixture['quality']}, 'epoch')
        self.now += 1_000_000_000

    def trigger(self):
        self.ingest()
        self.ingest()

    def test_snapshot_explains_actual_thresholds_and_suspicion_streak(self):
        self.ingest()
        first=self.pipeline.snapshot()
        row=first['hosts']['reception1']
        self.assertEqual(row['detection']['thresholds'],self.engine.config['thresholds']['admin'])
        self.assertEqual(row['detection']['anomalous_streak'],1)
        self.assertEqual(first['detection_policy']['anomalous_windows'],2)
        self.ingest()
        self.assertEqual(self.pipeline.snapshot()['hosts']['reception1']['detection']['anomalous_streak'],2)

    def test_observe_never_calls_mutation(self):
        self.pipeline.enforce = False
        self.trigger()
        asyncio.run(self.pipeline.reconcile())
        self.assertFalse(self.client.sent)
        self.assertFalse(self.pipeline.queue)
        self.assertEqual(self.pipeline.latest['reception1']['desired_state'], 'CONTAINED')
        self.assertFalse(self.pipeline.observed)

    def test_queued_is_not_confirmed_and_confirmation_is_separate(self):
        self.trigger()
        asyncio.run(self.pipeline.reconcile())
        self.assertIsNotNone(self.pipeline.pending)
        self.assertFalse(self.pipeline.observed)
        asyncio.run(self.pipeline.reconcile())
        self.assertEqual(self.pipeline.observed['reception1']['status'], 'pending')
        self.client.status['actions'][0]['status'] = 'confirmed'
        asyncio.run(self.pipeline.reconcile())
        self.assertIsNone(self.pipeline.pending)
        self.assertEqual(self.pipeline.observed['reception1']['status'], 'confirmed')

    def test_censored_clean_windows_cannot_release_and_ttl_can(self):
        self.trigger()
        for _ in range(5):
            self.ingest(suspect=False)
        self.assertEqual(len(self.pipeline.queue), 1)
        self.assertTrue(self.pipeline.latest['reception1']['evidence_censored'])
        self.now += 30_000_000_000
        self.ingest(suspect=False)
        self.assertEqual(self.pipeline.queue[-1]['action']['action'], 'RELEASE')

    def test_busy_retains_identical_proposal_but_uncertain_write_halts(self):
        self.trigger()
        first = self.pipeline.queue[0]
        self.client.error = ActionBusy('busy')
        asyncio.run(self.pipeline.reconcile())
        self.assertIs(self.pipeline.queue[0], first)
        self.assertIsNone(self.pipeline.halted)
        self.client.error = TimeoutError('response lost')
        asyncio.run(self.pipeline.reconcile())
        self.assertIn('no retry', self.pipeline.halted)
        asyncio.run(self.pipeline.reconcile())
        self.assertFalse(self.client.sent)

    def test_previous_planner_and_epoch_changes_halt_writes(self):
        self.trigger()
        self.client.status['actions'] = [{'proposal_id': 'unknown', 'host': 'guest1'}]
        asyncio.run(self.pipeline.reconcile())
        self.assertIn('Existing planner', self.pipeline.halted)
        self.pipeline.ingest({'status': 'invalid', 'features': [], 'quality': {}}, 'new-epoch')
        self.assertIn('restarted', self.pipeline.halted)

    def test_failure_and_event_gap_never_become_confirmed(self):
        self.trigger()
        asyncio.run(self.pipeline.reconcile())
        self.client.status['actions'][0].update(status='failed', error='wrong readback')
        asyncio.run(self.pipeline.reconcile())
        self.assertIn('Switch action failed', self.pipeline.halted)
        self.assertEqual(self.pipeline.observed['reception1']['status'], 'failed')

    def test_snapshot_atomic_and_contract_events(self):
        tagged = LivePipeline(self.engine,self.client,run_id='b'*32)
        self.assertEqual(tagged.emit('scored','reception1',{})['event']['run_id'],'b'*32)
        with self.assertRaises(ValueError):
            LivePipeline(self.engine,self.client,run_id='bad')
        self.trigger()
        self.assertLessEqual(len(self.pipeline.events), 256)
        for row in self.pipeline.events:
            self.assertEqual(set(row['event']), {'run_id', 'timestamp_ns', 'stage', 'host', 'details'})
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'status.json'
            write_snapshot(p, self.pipeline.snapshot())
            self.assertTrue(p.is_file())
            self.assertFalse(p.with_suffix('.tmp').exists())


if __name__ == '__main__':
    unittest.main()
