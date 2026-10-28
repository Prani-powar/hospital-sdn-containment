"""Loopback dashboard: controller bridge, fresh evidence snapshots, and authenticated override proxy."""
from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

_PERMITTED_OVERRIDE_ACTIONS = frozenset({'ISOLATE', 'RESTRICT', 'PROTECT', 'RELEASE'})
_MAX_OVERRIDE_BODY = 16 * 1024  # 16 KB – matches controller limit

ROOT = Path(__file__).resolve().parent
MAX_LOCAL = 2*1024*1024


def fresh_snapshot(path: Path, epoch: str) -> dict | None:
    """Bound reads and reject malformed, stale, stopped or wrong-process evidence."""
    if not isinstance(epoch,str) or not epoch:
        return None
    try:
        with path.open('rb') as stream:
            raw = stream.read(MAX_LOCAL+1)
        if len(raw)>MAX_LOCAL:
            return None
        value = json.loads(raw)
        if not isinstance(value,dict) or type(value.get('timestamp_ns')) is not int:
            return None
        age = time.monotonic_ns()-value['timestamp_ns']
        if (value.get('schema_version')!=1 or value.get('controller_epoch')!=epoch
                or value.get('quality')=='stopped' or value.get('stopped') is True
                or not 0<=age<=5_000_000_000):
            return None
        return value
    except (OSError,ValueError,TypeError,KeyError):
        return None


def decision_snapshot(path: Path, epoch: str) -> dict | None:
    value = fresh_snapshot(path,epoch)
    if (value is None or not isinstance(value.get('hosts'),dict) or len(value['hosts'])>24
            or not isinstance(value.get('actions'),list) or len(value['actions'])>24
            or not isinstance(value.get('events',[]),list) or len(value.get('events',[]))>256):
        return None
    return value


def clinical_snapshot(path: Path, epoch: str) -> dict | None:
    value = fresh_snapshot(path,epoch)
    if value is None:
        return None
    report = value.get('measurement')
    if not isinstance(report,dict) or not isinstance(report.get('services'),list):
        return None
    services = report['services']
    if (len(services)!=5 or any(not isinstance(v,dict) for v in services)
            or {v.get('flow_id') for v in services}!={'C1','C2','C3','C4','C5'}
            or any(not isinstance(v.get('sources'),list) or len(v['sources'])>8 for v in services)):
        return None
    expected = {'C1':{'monitor1','monitor2','monitor3'},'C2':{'pump1','pump2'},
        'C3':{'imaging1'},'C4':{'nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'},'C5':{'lis'}}
    for service in services:
        rows = service['sources']
        if (any(not isinstance(v,dict) for v in rows)
                or len(rows)!=len(expected[service['flow_id']])
                or {r.get('source') for r in rows}!=expected[service['flow_id']]):
            return None
        for row in rows:
            if (type(row.get('attempted')) is not int or type(row.get('received')) is not int
                    or not 0<=row['received']<=row['attempted']):
                return None
            if report.get('status')=='PASS' and (row['attempted']==0
                    or row['received']!=row['attempted'] or row.get('status')!='PASS'
                    or row.get('invalid_records')!=0):
                return None
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def make_handler(controller_port: int):
    """Fixed upstream endpoints; no arbitrary proxy URLs or write routes."""
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,directory=str(ROOT),**kwargs)

        def do_GET(self):
            port = self.server.server_port
            origins = {f'http://127.0.0.1:{port}',f'http://localhost:{port}'}
            hosts = {f'127.0.0.1:{port}',f'localhost:{port}'}
            if self.headers.get('Host') not in hosts or (
                    self.headers.get('Origin') and self.headers['Origin'] not in origins):
                self.send_error(403,'Local dashboard origin required')
                return
            if self.path=='/api/snapshot':
                try:
                    payload = {}
                    opener = build_opener(ProxyHandler({}),NoRedirect())
                    for name,endpoint in (('health','/v1/health'),('stats','/v1/stats')):
                        try:
                            response = opener.open(f'http://127.0.0.1:{controller_port}{endpoint}',timeout=2)
                        except HTTPError as exc:
                            if name!='health' or exc.code!=503:
                                raise
                            response = exc
                        with response:
                            raw = response.read(4*1024*1024+1)
                        if len(raw)>4*1024*1024:
                            raise ValueError('Controller response exceeds 4 MB')
                        payload[name] = json.loads(raw)
                        if not isinstance(payload[name],dict):
                            raise ValueError('Controller returned a non-object response')
                    epoch = payload['health'].get('controller_epoch')
                    payload['decision'] = decision_snapshot(ROOT.parent/'artifacts'/'decision-status.json',epoch)
                    payload['clinical'] = clinical_snapshot(ROOT.parent/'artifacts'/'critical-status.json',epoch)
                    raw = json.dumps(payload,allow_nan=False).encode()
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Cache-Control','no-store')
                    self.send_header('Content-Length',str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception:
                    self.send_error(502,'Controller unavailable or invalid telemetry')
                return
            if self.path.startswith('/api/'):
                self.send_error(404)
                return
            super().do_GET()

        def do_POST(self):
            """Forward authenticated override actions to the controller's /v1/actions."""
            port = self.server.server_port
            origins = {f'http://127.0.0.1:{port}', f'http://localhost:{port}'}
            hosts_allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if self.headers.get('Host') not in hosts_allowed or (
                    self.headers.get('Origin') and self.headers['Origin'] not in origins):
                self.send_error(403, 'Local dashboard origin required')
                return
            if self.path != '/api/action':
                self.send_error(404)
                return
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer ') or not auth.isascii() or len(auth) > 263:
                self.send_error(401, 'Missing or malformed Authorization header')
                return
            clen = self.headers.get('Content-Length')
            try:
                clen = int(clen)
                if not 1 <= clen <= _MAX_OVERRIDE_BODY:
                    raise ValueError
            except (TypeError, ValueError):
                self.send_error(413, 'Override body must be 1..' + str(_MAX_OVERRIDE_BODY) + ' bytes')
                return
            raw = self.rfile.read(clen)
            try:
                proposal = json.loads(raw)
                if not isinstance(proposal, dict):
                    raise ValueError('Proposal must be a JSON object')
                action_field = proposal.get('action', {})
                if not isinstance(action_field, dict):
                    raise ValueError('action field must be an object')
                action_name = action_field.get('action', '')
                if action_name not in _PERMITTED_OVERRIDE_ACTIONS:
                    raise ValueError(f'action must be one of {sorted(_PERMITTED_OVERRIDE_ACTIONS)}')
            except (ValueError, json.JSONDecodeError) as exc:
                body = json.dumps({'error': str(exc)[:256]}).encode()
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            # Forward to controller
            try:
                conn = http.client.HTTPConnection('127.0.0.1', controller_port, timeout=8)
                conn.request('POST', '/v1/actions', body=raw,
                             headers={'Authorization': auth,
                                      'Content-Type': 'application/json',
                                      'Accept': 'application/json',
                                      'Content-Length': str(len(raw))})
                resp = conn.getresponse()
                data = resp.read(256 * 1024)
                conn.close()
                self.send_response(resp.status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:
                body = json.dumps({'error': 'Controller unavailable: ' + str(exc)[:128]}).encode()
                self.send_response(502)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8088)
    parser.add_argument('--controller-port',type=int,default=18080)
    args = parser.parse_args()
    if not all(1024<=port<=65535 for port in (args.port,args.controller_port)):
        parser.error('Ports must be in 1024..65535')
    server = ThreadingHTTPServer(('127.0.0.1',args.port),make_handler(args.controller_port))
    print(f'MedSeg dashboard: http://127.0.0.1:{args.port}',flush=True)
    print('Simulation by default. Live mode is read-only. Press Ctrl+C to stop.',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=='__main__':
    main()
