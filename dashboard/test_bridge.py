"""Freshness and controller identity checks for actual decision snapshot imports."""
import json
from pathlib import Path
import tempfile
import time
import unittest

from dashboard.serve import decision_snapshot


class BridgeTests(unittest.TestCase):
    def test_snapshot_requires_matching_epoch_fresh_clock_and_running_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'status.json'
            body={'schema_version':1,'controller_epoch':'epoch','timestamp_ns':time.monotonic_ns(),
                  'quality':'ready','hosts':{},'actions':[]}
            path.write_text(json.dumps(body))
            self.assertIsNotNone(decision_snapshot(path,'epoch'))
            self.assertIsNone(decision_snapshot(path,'other'))
            for updates in ({'timestamp_ns':0},{'timestamp_ns':time.monotonic_ns()+10**10},
                            {'quality':'stopped'},{'hosts':{str(i):{} for i in range(25)}}):
                path.write_text(json.dumps(dict(body,**updates)))
                self.assertIsNone(decision_snapshot(path,'epoch'))
            path.write_text('{broken')
            self.assertIsNone(decision_snapshot(path,'epoch'))


class ExtendedSnapshotTests(unittest.TestCase):
    def test_non_object_corrupt_or_missing_identity_never_breaks_telemetry(self):
        from dashboard.serve import fresh_snapshot
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'status.json'
            for value in ([],None,'bad',{'timestamp_ns':True},{}):
                p.write_text(json.dumps(value))
                self.assertIsNone(fresh_snapshot(p,'epoch'))
            self.assertIsNone(fresh_snapshot(p,None))

    def test_clinical_success_requires_every_configured_source_and_nonzero_replies(self):
        from dashboard.serve import clinical_snapshot
        expected={'C1':['monitor1','monitor2','monitor3'],'C2':['pump1','pump2'],'C3':['imaging1'],
            'C4':['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'],'C5':['lis']}
        services=[{'flow_id':flow,'sources':[{'source':name,'attempted':3,'received':3,
                     'status':'PASS','invalid_records':0} for name in names]} for flow,names in expected.items()]
        body={'schema_version':1,'controller_epoch':'epoch','timestamp_ns':time.monotonic_ns(),
              'measurement':{'status':'PASS','services':services}}
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'status.json'
            p.write_text(json.dumps(body))
            self.assertIsNotNone(clinical_snapshot(p,'epoch'))
            body['measurement']['services'][0]['sources'][0]['received']=0
            p.write_text(json.dumps(body))
            self.assertIsNone(clinical_snapshot(p,'epoch'))
            body['measurement']['status']='FAIL'
            p.write_text(json.dumps(body))
            self.assertIsNotNone(clinical_snapshot(p,'epoch'))
            body['measurement']['services'][0]['sources'].pop()
            p.write_text(json.dumps(body))
            self.assertIsNone(clinical_snapshot(p,'epoch'))


class HttpBridgeTests(unittest.TestCase):
    def test_real_http_degraded_health_origin_gate_no_post_or_arbitrary_proxy(self):
        import http.client
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        import threading
        from unittest.mock import patch
        from dashboard.serve import make_handler
        requests=[]
        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                raw=json.dumps({'controller_epoch':'epoch','status':'degraded'} if self.path=='/v1/health'
                               else {'switches':[],'complete':False}).encode()
                self.send_response(503 if self.path=='/v1/health' else 200)
                self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        handler=make_handler(upstream.server_port)
        handler.log_message=lambda *args:None
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (upstream,server)]
        for t in threads:t.start()
        def request(path='/api/snapshot',method='GET',headers=None):
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            try:
                c.request(method,path,headers=headers or {})
                response=c.getresponse();return response.status,response.read()
            finally:c.close()
        try:
            with tempfile.TemporaryDirectory() as tmp,patch('dashboard.serve.ROOT',Path(tmp)/'dashboard'):
                status,raw=request()
                self.assertEqual(status,200)
                body=json.loads(raw)
                self.assertEqual(body['health']['status'],'degraded')
                self.assertIsNone(body['decision'])
                self.assertIsNone(body['clinical'])
                self.assertEqual(requests,['/v1/health','/v1/stats'])
                self.assertEqual(request(headers={'Origin':'https://elsewhere.invalid'})[0],403)
                self.assertEqual(request(headers={'Host':'elsewhere.invalid'})[0],403)
                self.assertEqual(request('/api/snapshot?url=http://example.invalid')[0],404)
                self.assertEqual(request(method='POST')[0],404)
                self.assertEqual(request('/api/action',method='POST')[0],401)
                self.assertEqual(request('/api/action',method='POST',headers={'Origin':'https://elsewhere.invalid'})[0],403)
                self.assertEqual(len(requests),2)
        finally:
            for s in (server,upstream):s.shutdown();s.server_close()
            for t in threads:t.join(timeout=2)

    def test_http_redirect_is_rejected_without_following_it(self):
        import http.client
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        import threading
        from dashboard.serve import make_handler
        requests=[]
        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header('Location','/redirect-target')
                self.end_headers()
            def log_message(self,*args):pass
        upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        handler=make_handler(upstream.server_port);handler.log_message=lambda *args:None
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (upstream,server)]
        for t in threads:t.start()
        try:
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            c.request('GET','/api/snapshot');response=c.getresponse();response.read();c.close()
            self.assertEqual(response.status,502)
            self.assertEqual(requests,['/v1/health'])
        finally:
            for s in (server,upstream):s.shutdown();s.server_close()
            for t in threads:t.join(timeout=2)
