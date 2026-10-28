"""Actual local UDP workers and suite evidence tests; no Mininet/OVS claim."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

import yaml

from topology.clinical import packet, reply_allowed
from topology.critical_suite import CriticalSuite, load_config, read_probes
from topology.hospital import load_plan

ROOT = Path(__file__).resolve().parents[2]


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.topology = load_plan(ROOT/'configs/hospital.yaml')
        self.config = load_config(ROOT/'configs/critical-suite.yaml', self.topology)

    def test_config_matches_all_five_floor_services_and_is_bounded(self):
        self.assertEqual([v['flow_id'] for v in self.config['services']], ['C1','C2','C3','C4','C5'])
        self.assertEqual(sum(len(v['sources']) for v in self.config['services']), 13)
        self.assertEqual([v['udp_port'] for v in self.config['services']], list(range(18001,18006)))
        original = yaml.safe_load((ROOT/'configs/critical-suite.yaml').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'bad.yaml'
            for updates in ({'rate_hz':11},{'duration_s':181},{'rate_hz':True},
                            {'reply_timeout_s':float('nan')},{'variant':'unknown'}, {'extra':1}):
                path.write_text(yaml.safe_dump(dict(original, **updates)))
                with self.assertRaises(ValueError):
                    load_config(path, self.topology)

    def test_flow_identity_prevents_cross_service_echo(self):
        raw = packet('run','pump1',1,10,'C2')
        self.assertTrue(reply_allowed(raw, {'pump1'}, 'run', 'C2'))
        self.assertFalse(reply_allowed(raw, {'pump1'}, 'run', 'C3'))
        self.assertFalse(reply_allowed(raw, {'pump1'}, 'other', 'C2'))
        self.assertFalse(reply_allowed(raw, {'monitor1'}, 'run', 'C2'))

    def test_phase_evidence_ignores_stale_and_rejects_duplicate_foreign_or_invalid_rows(self):
        row = {'check':'c2_probe','run_id':'r','source':'pump1','seq':1,
               'timestamp_ns':20,'success':True,'rtt_ms':.2}
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'pump1.jsonl'
            records = [dict(row,timestamp_ns=5), row, row,
                       dict(row,seq=2,run_id='other'), dict(row,seq=3,rtt_ms=float('nan')),
                       dict(row,seq=4,success=False,rtt_ms=None)]
            p.write_text('\n'.join(json.dumps(v) for v in records)+'\n{"incomplete":')
            result = read_probes(p,'r','C2','pump1',10,30)
            self.assertEqual(len(result['records']), 2)
            self.assertEqual(result['invalid_records'], 4)
            self.assertEqual(sum(r['success'] for r in result['records']), 1)
            self.assertFalse(read_probes(p,'r','C3','pump1',10,30)['records'])

    def test_no_workers_or_empty_logs_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = CriticalSuite(None, self.config, Path(tmp))
            self.assertEqual(suite.summary(1,10)['status'], 'unmeasured')
            suite.stop()
            tagged = CriticalSuite(None,self.config,Path(tmp),run_id='a'*32)
            self.assertEqual(tagged.run_id,'a'*32)
            with self.assertRaises(ValueError):
                CriticalSuite(None,self.config,Path(tmp),run_id='../unsafe')

    def test_partial_failure_stops_every_started_session(self):
        class Host:
            def popen(self, *args, **kwargs):
                raise OSError('Controlled launch failure')
        class Network:
            def get(self, name):
                return Host()
        with tempfile.TemporaryDirectory() as tmp:
            suite = CriticalSuite(Network(), self.config, Path(tmp))
            with self.assertRaises(OSError):
                suite.start()
            suite.stop()
            self.assertTrue(all(s.closed for v in suite.sessions for s in v.streams))

    def test_real_all_five_local_udp_sessions_and_cleanup(self):
        class Host:
            def popen(self, args, **kwargs):
                return subprocess.Popen(args, **kwargs)
        class Network:
            def get(self, name):
                return Host()
        config = copy.deepcopy(self.config)
        reservations = []
        for service in config['services']:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1',0))
            service.update(server_ip='127.0.0.1', udp_port=sock.getsockname()[1],
                           duration_s=1, rate_hz=5, startup_timeout_s=2)
            reservations.append(sock)
        for sock in reservations:
            sock.close()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            suite = CriticalSuite(Network(), config, Path(tmp))
            start = time.monotonic_ns()
            try:
                suite.start()
                for session in suite.sessions:
                    for host, p in session.processes:
                        if host in session.config['sources']:
                            self.assertEqual(p.wait(timeout=5),0)
                # Use exact worker evidence here, not a minimum-rate gate across
                # sequential startup; each configured worker must actually echo.
                for session in suite.sessions:
                    for source in session.config['sources']:
                        rows = read_probes(session.directory/f'{source}.jsonl',suite.run_id,
                            session.config['flow_id'],source,start,time.monotonic_ns())
                        self.assertGreater(len(rows['records']),0)
                        self.assertEqual(rows['invalid_records'],0)
                        self.assertTrue(all(v['success'] for v in rows['records']))
            finally:
                suite.stop()
            self.assertTrue(all(p.poll() is not None for s in suite.sessions for _,p in s.processes))
