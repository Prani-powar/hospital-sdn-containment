"""Actual local HTTP writes/status reads; no real switch-enforcement claim."""
import asyncio
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import threading
import unittest

from controller.action_client import ActionBusy,ControllerClient,action_request


class ClientActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls=[];self.entered=threading.Event();self.release=threading.Event()
        self.slow=False;self.busy=False;self.epoch='epoch';self.reads=0
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.calls.append('POST')
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                outer.entered.set()
                if outer.slow:outer.release.wait(timeout=2)
                self.respond(409 if outer.busy else 202,
                    {'error':'busy'} if outer.busy else {'proposal_id':body['proposal_id'],'status':'pending'})
            def do_GET(self):
                outer.calls.append('GET');outer.reads+=1
                self.respond(200,{'controller_epoch':outer.epoch,'actions':[
                    {'proposal_id':'a'*64,'status':'confirmed' if outer.reads>=2 else 'pending'}]})
            def respond(self,status,body):
                if self.headers.get('Authorization')!='Bearer '+'x'*32:status,body=401,{'error':'unauthorized'}
                raw=json.dumps(body).encode();self.send_response(status)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'
        self.client=ControllerClient('x'*32,self.base)
        self.proposal={'proposal_id':'a'*64,'controller_epoch':'epoch','action':{'action':'ISOLATE'}}

    def tearDown(self):
        self.release.set();self.server.shutdown();self.server.server_close();self.worker.join(timeout=2)

    async def test_pending_is_not_confirmed_and_no_automatic_post_retries(self):
        result=await self.client.push_rule(self.proposal)
        self.assertEqual(result['status'],'pending')
        result=await self.client.wait_confirmed(self.proposal,timeout_s=2)
        self.assertEqual(result['status'],'confirmed')
        self.assertEqual(self.calls.count('POST'),1)
        self.assertGreaterEqual(self.calls.count('GET'),2)

    async def test_busy_auth_and_epoch_errors_do_not_replay_writes(self):
        self.busy=True
        with self.assertRaises(ActionBusy):await self.client.push_rule(self.proposal)
        self.assertEqual(self.calls,['POST'])
        bad=ControllerClient('z'*32,self.base)
        with self.assertRaises(RuntimeError):await bad.get_actions()
        self.epoch='restarted'
        with self.assertRaisesRegex(RuntimeError,'restarted'):
            await self.client.wait_confirmed(self.proposal,timeout_s=1)
        self.assertEqual(self.calls.count('POST'),1)

    async def test_cancelled_write_keeps_worker_slot_until_underlying_http_finishes(self):
        self.slow=True
        first=asyncio.create_task(self.client.push_rule(self.proposal))
        while not self.entered.is_set():await asyncio.sleep(0.005)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):await first
        second=asyncio.create_task(self.client.get_actions())
        await asyncio.sleep(0.03)
        self.assertEqual(self.calls,['POST'])
        self.release.set();await second
        self.assertEqual(self.calls,['POST','GET'])

    async def test_payload_endpoint_and_release_contract_checks(self):
        with self.assertRaises(ValueError):action_request('http://example.com','x'*32,None,1)
        with self.assertRaises(ValueError):action_request(self.base,'x'*32,{'data':'a'*20000},1)
        with self.assertRaises(ValueError):await self.client.remove_rule(self.proposal)
        with self.assertRaises(ValueError):await self.client.push_rule({'action':{'action':'RELEASE'}})
        self.assertFalse(self.calls)


if __name__=='__main__':unittest.main()
