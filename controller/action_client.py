"""Authenticated local ControllerClient mutation boundary with explicit confirmation."""
from __future__ import annotations

import asyncio
import http.client
import json
import re
from urllib.parse import urlsplit

from controller.telemetry_client import MAX_RESPONSE_BYTES, TelemetryClient


def action_request(base_url: str,token: str,proposal: dict|None,timeout_s: float) -> tuple[int,dict]:
    url=urlsplit(base_url)
    if (url.scheme!='http' or url.hostname!='127.0.0.1' or url.username or url.password
            or url.path not in ('','/') or url.query or url.fragment):
        raise ValueError('Action client requires http://127.0.0.1:PORT')
    if not 32<=len(token)<=256 or not token.isascii() or '\n' in token or '\r' in token:
        raise ValueError('Invalid action token')
    if not 0.1<=timeout_s<=10:raise ValueError('Invalid HTTP timeout')
    raw=json.dumps(proposal,allow_nan=False).encode() if proposal is not None else None
    if raw is not None and len(raw)>16384:raise ValueError('Action payload exceeds 16 KB')
    connection=http.client.HTTPConnection(url.hostname,url.port or 80,timeout=timeout_s)
    try:
        connection.request('POST' if proposal is not None else 'GET','/v1/actions',body=raw,
            headers={'Authorization':'Bearer '+token,'Accept':'application/json','Content-Type':'application/json'})
        response=connection.getresponse()
        data=response.read(MAX_RESPONSE_BYTES+1)
        if len(data)>MAX_RESPONSE_BYTES:raise ValueError('Action response exceeds size bound')
        body=json.loads(data)
        if not isinstance(body,dict):raise ValueError('Invalid action response')
        return response.status,body
    finally:connection.close()


class ActionBusy(RuntimeError):
    """No reservation was accepted; retry only the identical proposal after readback."""


class ControllerClient(TelemetryClient):
    """Read statistics and submit explicit versioned plans; never blindly retry a write."""
    def __init__(self,token: str,base_url: str='http://127.0.0.1:18080',timeout_s: float=2.0) -> None:
        super().__init__(base_url,timeout_s,concurrency=1)
        self.token=token

    async def _submit(self,proposal: dict) -> dict:
        status,body=await self._run(action_request,self.base_url,self.token,proposal,self.timeout_s)
        if status==409:raise ActionBusy(body.get('error','Controller busy'))
        if status not in (200,202):raise RuntimeError(f'Action rejected (HTTP {status}): '+str(body.get('error',''))[:256])
        return body

    async def push_rule(self,proposal: dict) -> dict:
        if proposal.get('action',{}).get('action') not in ('ISOLATE','RESTRICT','PROTECT'):
            raise ValueError('push_rule requires a containment proposal')
        return await self._submit(proposal)

    async def remove_rule(self,proposal: dict) -> dict:
        if proposal.get('action',{}).get('action')!='RELEASE':
            raise ValueError('remove_rule requires a RELEASE proposal')
        return await self._submit(proposal)

    async def get_actions(self) -> dict:
        status,body=await self._run(action_request,self.base_url,self.token,None,self.timeout_s)
        if status!=200:raise RuntimeError(f'Action status unavailable (HTTP {status})')
        return body

    async def wait_confirmed(self,proposal: dict,timeout_s: float=20) -> dict:
        """Queued is not installed; wait for barrier plus actual rule-table confirmation."""
        if not 1<=timeout_s<=30:raise ValueError('Confirmation timeout must be 1..30 seconds')
        if not re.fullmatch('[0-9a-f]{64}',proposal.get('proposal_id','')):raise ValueError('Invalid proposal id')
        loop=asyncio.get_running_loop();deadline=loop.time()+timeout_s
        while loop.time()<deadline:
            status=await self.get_actions()
            if status.get('controller_epoch')!=proposal['controller_epoch']:
                raise RuntimeError('Controller restarted; actual-rule reconciliation required')
            result=next((r for r in status.get('actions',[]) if r.get('proposal_id')==proposal['proposal_id']),None)
            if result:
                if result['status']=='confirmed':return result
                if result['status']=='failed':raise RuntimeError(result.get('error','Action failed'))
            await asyncio.sleep(0.2)
        raise TimeoutError('No switch-confirmed action within confirmation deadline')
