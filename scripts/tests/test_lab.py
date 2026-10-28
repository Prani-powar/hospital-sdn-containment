import json
import threading
import unittest
import http.client
from types import SimpleNamespace
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from scripts.lab import Controls, handler, current_drop_proof, confirmed_actions_since
from controller.enforcement import ACTION_PREFIX

class LabTests(unittest.TestCase):
    def test_commands_reject_unknown_and_double_launch(self):
        c=Controls(['billing1']);c.update(ready=True)
        with self.assertRaises(ValueError):c.submit({'host':'ehr'})
        c.submit({'host':'billing1'})
        with self.assertRaises(ValueError):c.submit({'host':'billing1'})
        self.assertEqual(c.commands.get_nowait(),'billing1')
        c.update(ready=True);c.submit({'host':'billing1'})
        self.assertFalse(c.snapshot()['ready'])
    def test_events_are_bounded(self):
        c=Controls([])
        for n in range(100):c.event(str(n))
        self.assertEqual(len(c.snapshot()['events']),40)
    def test_mutations_require_local_origin_and_json(self):
        c=Controls(['billing1']);c.update(ready=True)
        server=ThreadingHTTPServer(('127.0.0.1',0),handler(c))
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            port=server.server_port
            for origin,ctype,expected in [(None,'application/json',403),('http://evil.example','application/json',403),(f'http://127.0.0.1:{port}','text/plain',403),(f'http://127.0.0.1:{port}','application/json',202)]:
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=2)
                headers={'Content-Type':ctype}
                if origin:headers['Origin']=origin
                conn.request('POST','/api/lab/scenario',json.dumps({'host':'billing1'}),headers)
                r=conn.getresponse();self.assertEqual(r.status,expected);r.read();conn.close()
        finally:server.shutdown();server.server_close();thread.join()
    def test_drop_proof_requires_both_directions_every_switch(self):
        topology={'hosts':[{'name':'billing1','ip':'10.20.0.3/24'}],'switches':[{'name':'s1'},{'name':'s2'}]}
        good=' cookie=0x1, priority=40000,ip,nw_src=10.20.0.3 actions=drop\n cookie=0x2, priority=40000,ip,nw_dst=10.20.0.3 actions=drop'
        with patch('scripts.lab.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=good)) as call:
            self.assertTrue(current_drop_proof(topology,'billing1','ISOLATE',2))
            self.assertEqual(call.call_count,2)
            self.assertIn(f'cookie=0x{ACTION_PREFIX|(1<<40)|(2<<16):x}/0xffffffffffff0000',call.call_args.args[0])
        with patch('scripts.lab.subprocess.run',side_effect=[SimpleNamespace(returncode=0,stdout=good),SimpleNamespace(returncode=0,stdout=good.splitlines()[0])]):
            self.assertFalse(current_drop_proof(topology,'billing1','ISOLATE',2))
    def test_prefix_ip_does_not_count_as_exact_source(self):
        t={'hosts':[{'name':'billing1','ip':'10.20.0.3/24'}],'switches':[{'name':'s1'}]}
        with patch('scripts.lab.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=' priority=40000,ip,nw_src=10.20.0.30 actions=drop')):
            self.assertFalse(current_drop_proof(t,'billing1','RESTRICT',1))

    def test_stale_session_cannot_launch_or_claim_containment(self):
        c=Controls(['billing1']);c.update(ready=True,containment={'current':True,'checked_ns':1})
        c.updated_ns=1
        self.assertFalse(c.snapshot()['ready'])
        self.assertFalse(c.snapshot()['containment']['current'])
        with self.assertRaises(ValueError):c.submit({'host':'billing1'})

    def test_pending_null_timestamp_does_not_crash_or_confirm(self):
        rows=[{'host':'billing1','status':'pending','confirmed_ns':None},
              {'host':'billing1','status':'failed','confirmed_ns':None},
              {'host':'billing1','status':'confirmed','confirmed_ns':None},
              {'host':'billing1','status':'confirmed','confirmed_ns':99},
              {'host':'guest1','status':'confirmed','confirmed_ns':101},
              {'host':'billing1','status':'confirmed','confirmed_ns':101}]
        self.assertEqual(confirmed_actions_since(rows,'billing1',100),[rows[-1]])
