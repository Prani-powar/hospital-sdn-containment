"""Pure rule compiler and bounded acknowledgement/readback transaction coordinator."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

import yaml

from controller.core import Fabric, TokenBucket
from topology.hospital import UniqueKeyLoader, require
from topology.restriction_demo import route

FLOOR_PREFIX = 0xC150000000000000
FLOOR_MASK = 0xFFFF000000000000
ACTION_PREFIX = 0xD440000000000000
HOST_MASK = 0xFFFFFF0000000000
FULL_MASK = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class Rule:
    """Only the compiler creates rules; delete operations retain full cookie identity."""
    dpid: int
    cookie: int
    priority: int
    match_json: str
    output: int | None
    hard_timeout: int

    @property
    def match(self) -> dict:
        return json.loads(self.match_json)

    @property
    def identity(self) -> tuple:
        return self.dpid, self.cookie, self.priority, self.match_json, self.output

    def row(self) -> dict:
        return {'cookie': self.cookie, 'priority': self.priority, 'match': self.match,
                'output': self.output, 'hard_timeout': self.hard_timeout, 'table_id': 0}


def load_enforcement(path: Path, fabric: Fabric) -> dict:
    require(path.stat().st_size <= 100_000, 'Enforcement config too large')
    c = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(c, dict) and c.get('schema_version') == 1, 'Invalid enforcement schema')
    require(c.get('variant') in ('synthetic-c1-c5-protected-floor-v1',
            'synthetic-c1-c5-scaled-research-v1'), 'Unknown floor variant')
    for key, lo, hi in [('max_timeout_s',1,40),('exception_margin_s',16,20),
                        ('transaction_timeout_s',4,15),('reply_timeout_s',1,3),
                        ('flow_mod_rate',20,200),('flow_mod_burst',20,200),
                        ('max_ops_per_tick',1,20),('max_rows',128,4096),('max_parts',1,32)]:
        require(type(c.get(key)) is int and lo<=c[key]<=hi, f'Invalid {key}')
    require(c['exception_margin_s'] > c['transaction_timeout_s'], 'Exceptions must outlive transaction plus drop')
    require(isinstance(c.get('critical_services'),list) and len(c['critical_services'])==5,
            'All five synthetic clinical service definitions are required')
    require(isinstance(c.get('peer_services'),dict) and set(c['peer_services'])<=fabric.hosts.keys(), 'Invalid service peers')
    require(isinstance(c.get('management_services'),list) and 0<len(c['management_services'])<=24, 'Management service required')
    for service in c['critical_services']:
        require(isinstance(service,dict) and service.get('server') in fabric.hosts
                and isinstance(service.get('sources'),list) and 0<len(service['sources'])<=24
                and all(isinstance(h,str) and h in fabric.hosts and h!=service['server'] for h in service['sources']),
                'Invalid critical source/server')
        require(fabric.hosts[service['server']]['role']=='critical_server'
                and all(fabric.hosts[h]['role'] in ('iomt','clinical','critical_server')
                        for h in service['sources']), 'Critical floor cannot exempt office/guest/vendor sources')
    expected = [
        (('monitor1','monitor2','monitor3'),'central_mon','udp',18001),
        (('pump1','pump2'),'ehr','udp',18002),
        (('imaging1',),'pacs','udp',18003),
        (('nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'),'ehr','udp',18004),
        (('lis',),'ehr','udp',18005)]
    actual = [(tuple(v['sources']),v['server'],v.get('protocol'),v.get('port'))
              for v in c['critical_services']]
    if c['variant'] == 'synthetic-c1-c5-protected-floor-v1':
        require(actual == expected, 'Named critical floor variant differs from its C1-C5 definitions')
    else:
        # Explicit research variant: retain all five services/ports and at least
        # one original source per group. Default clinical contract is unchanged.
        require(all(a[1:] == e[1:] and set(a[0]) <= set(e[0]) and a[0]
                    for a, e in zip(actual, expected)), 'Invalid scaled research floor')
    services = list(c['critical_services']) + c['management_services']
    for peer, entries in c['peer_services'].items():
        require(isinstance(entries,list) and len(entries)<=16, 'Invalid peer service count')
        services += entries
    for service in services:
        require(isinstance(service,dict) and service.get('protocol') in ('tcp','udp')
                and type(service.get('port')) is int and 1<=service['port']<=65535, 'Invalid service protocol/port')
        if 'peer' in service:
            require(service['peer'] in fabric.hosts, 'Invalid management peer')
    return c


class Compiler:
    """Compute explicit forward/reverse output ports; never use NORMAL or wildcard deletes."""
    def __init__(self, fabric: Fabric, settings: dict, policy: dict) -> None:
        self.fabric,self.settings,self.policy=fabric,settings,policy
        self.host_numbers={name:i+1 for i,name in enumerate(sorted(fabric.hosts))}
        self.by_switch={name:dpid for dpid,name in fabric.switches.items()}
        self.protected=set()
        floor=[]
        for service in settings['critical_services']:
            for source in service['sources']:
                self.protected.add((source,service['server']))
                self.protected.add((service['server'],source))
                floor.extend(self.service_rules(source,service['server'],service,FLOOR_PREFIX,50000,0))
        # Ordinals are unique even when logical flows share some matches.
        unique={ (r.dpid,r.priority,r.match_json,r.output):r for r in floor }
        self.floor=[Rule(r.dpid,FLOOR_PREFIX+i+1,r.priority,r.match_json,r.output,0)
                    for i,r in enumerate(unique.values())]
        require({tuple(p) for p in policy['protected_pairs']}<=self.protected,
                'Clinical floor omits a trusted protected pair')
        require(len(self.floor)<=256,'Clinical floor rule limit')

    def namespace(self, host: str) -> int:
        return ACTION_PREFIX | (self.host_numbers[host]<<40)

    def service_rules(self, source: str, destination: str, service: dict,
                      cookie: int, priority: int, ttl: int) -> list[Rule]:
        rules=[]
        for src,dst,field in [(source,destination,'dst'),(destination,source,'src')]:
            s,d=self.fabric.hosts[src],self.fabric.hosts[dst]
            for switch,out_port in route(self.fabric.topology,src,dst):
                dpid=self.by_switch[switch]
                match={'in_port':self.fabric.ports[(dpid,s['mac'])], 'eth_type':0x0800,
                       'ipv4_src':s['address'],'ipv4_dst':d['address'],
                       'ip_proto':6 if service['protocol']=='tcp' else 17,
                       service['protocol']+'_'+field:service['port']}
                rules.append(Rule(dpid,cookie,priority,json.dumps(match,sort_keys=True),out_port,ttl))
        return rules

    def compile(self, proposal: dict, epoch: str) -> tuple[str,list[Rule]]:
        require(isinstance(proposal,dict),'Expected proposal object')
        require('run_id' not in proposal or isinstance(proposal['run_id'],str)
                and re.fullmatch(r'[0-9a-f]{32}',proposal['run_id']), 'Invalid experiment run id')
        require(proposal.get('controller_epoch')==epoch,'Controller epoch mismatch')
        require(isinstance(proposal.get('planner_epoch'),str) and re.fullmatch(r'[0-9a-f]{32}',proposal['planner_epoch']), 'Invalid planner epoch')
        require(isinstance(proposal.get('proposal_id'),str) and re.fullmatch(r'[0-9a-f]{64}',proposal['proposal_id']), 'Invalid proposal id')
        require(type(proposal.get('version')) is int and 1<=proposal['version']<=65535,'Invalid action version')
        a=proposal.get('action')
        require(isinstance(a,dict) and set(a)=={'action','host','allowed_peers','timeout_s','reason'},'Action contract mismatch')
        name=a['host']; require(isinstance(name,str) and name in self.fabric.hosts,'Unknown host')
        kind=a['action']; require(kind in ('ISOLATE','RESTRICT','PROTECT','RELEASE'),'Unknown action')
        require(isinstance(a['reason'],str) and 0<len(a['reason'])<=512,'Invalid reason')
        peers=a['allowed_peers']
        require(isinstance(peers,list) and len(peers)<=24 and all(isinstance(p,str) and p in self.fabric.hosts and p!=name for p in peers)
                and len(set(peers))==len(peers),'Invalid action peers')
        role=self.fabric.hosts[name]['role']
        require(kind!='ISOLATE' or role in ('admin','guest','vendor'),'Protected role cannot be isolated')
        require(kind!='RESTRICT' or role in ('clinical','iomt','vendor'),'Unexpected restricted role')
        if kind=='RELEASE':
            require(a['timeout_s']==0 and not peers,'Release has no lease/allow peers')
            return name,[]
        require(type(a['timeout_s']) is int and 1<=a['timeout_s']<=self.settings['max_timeout_s'],'Invalid hard timeout')
        ttl=a['timeout_s']; rules=[]
        if kind=='PROTECT':
            src=proposal.get('malicious_source')
            require(role=='critical_server' and isinstance(src,str) and src in self.fabric.hosts and src!=name,'PROTECT requires a distinct attributed source')
            require((src,name) not in self.protected,'PROTECT conflicts with clinical floor; human review required')
            require(not peers,'PROTECT does not grant allowed peers')
            drop={'eth_type':0x0800,'ipv4_src':self.fabric.hosts[src]['address'],'ipv4_dst':self.fabric.hosts[name]['address']}
            first=self.fabric.hosts[src]['access_dpid']
            for dpid in [first]+[d for d in self.fabric.switches if d!=first]:
                rules.append(Rule(dpid,0,40000,json.dumps(drop,sort_keys=True),None,ttl))
        else:
            expected=set(self.policy['management_peers'])-{name} if kind=='ISOLATE' else set(
                self.policy['allowed_peer_overrides'].get(name,self.policy['allowed_peers_by_role'][role]))-{name}
            require(set(peers)==expected,'Action peer set differs from trusted policy')
            if kind=='ISOLATE':
                for service in self.settings['management_services']:
                    if service['peer'] in peers:
                        rules.extend(self.service_rules(name,service['peer'],service,0,45000,ttl+self.settings['exception_margin_s']))
                require(rules,'No management service exception could be compiled')
            else:
                for peer in peers:
                    entries=self.settings['peer_services'].get(peer,[])
                    require(entries,'No port-specific service for allowed peer')
                    for service in entries:
                        rules.extend(self.service_rules(name,peer,service,0,45000,ttl+self.settings['exception_margin_s']))
                for src,dst in self.protected:
                    if src==name:
                        require(dst in peers,'Restriction removes a vital peer')
            h=self.fabric.hosts[name]
            for dpid in [h['access_dpid']]+[d for d in self.fabric.switches if d!=h['access_dpid']]:
                for field in (['ipv4_src','ipv4_dst'] if kind=='ISOLATE' else ['ipv4_src']):
                    match={'eth_type':0x0800,field:h['address']}
                    rules.append(Rule(dpid,0,40000,json.dumps(match,sort_keys=True),None,ttl))
        unique={ (r.dpid,r.priority,r.match_json,r.output):r for r in rules }
        base=self.namespace(name)|(proposal['version']<<16)
        result=[Rule(r.dpid,base+i+1,r.priority,r.match_json,r.output,r.hard_timeout)
                for i,r in enumerate(unique.values())]
        require(len(result)<=128,'Containment rule limit')
        return name,result


class Transactions:
    """One active bounded transaction, with explicit acknowledgement and rule readback.

    Adapter.prepare must not yield. Adapter.queue may yield only after request
    tracking is registered. Adapter.connections returns current datapath objects.
    """
    def __init__(self, compiler: Compiler, adapter: object, epoch: str, clock=time.monotonic) -> None:
        self.compiler,self.adapter,self.epoch,self.clock=compiler,adapter,epoch,clock
        c=compiler.settings
        self.bucket=TokenBucket(c['flow_mod_rate'],c['flow_mod_burst'])
        self.active=None; self.results={}; self.owner=None; self.ready=False
        self.connection_signature=None; self.retry_after=0.0
        self.events=deque(maxlen=256); self.event_seq=0

    def emit(self,stage: str,host: str|None,details: dict) -> None:
        self.event_seq+=1
        run_id=(self.active or {}).get('proposal',{}).get('run_id',self.epoch)
        self.events.append({'seq':self.event_seq,'event':{'run_id':run_id,
                            'timestamp_ns':int(self.clock()*1e9), 'stage':stage,
                            'host':host,'details':details}})

    def submit(self, proposal: dict) -> tuple[int,dict]:
        name,rules=self.compiler.compile(proposal,self.epoch)
        fingerprint=hashlib.sha256(json.dumps(proposal,sort_keys=True).encode()).hexdigest()
        old=self.results.get(name)
        if old and old['proposal_id']==proposal['proposal_id']:
            require(old['fingerprint']==fingerprint,'Proposal id reused with different content')
            return (202 if old['status']=='pending' else 200),self.public(old)
        require(self.owner in (None,proposal['planner_epoch']),'Planner ownership differs; reconcile/restart required')
        require(old is None or proposal['version']>old['version'],'Stale host action version')
        if self.active or not self.ready:
            return 409,{'error':'Controller is busy or clinical floor is not confirmed; retry same proposal'}
        self.owner=proposal['planner_epoch']
        result={'proposal_id':proposal['proposal_id'],'version':proposal['version'],'fingerprint':fingerprint,
                'host':name,'status':'pending','action':proposal['action']['action'],
                'requested_ns':int(self.clock()*1e9),'confirmed_ns':None,'error':None}
        self.results[name]=result
        self.active={'id':proposal['proposal_id'],'host':name,'rules':rules,'result':result,
                     'deadline':self.clock()+self.compiler.settings['transaction_timeout_s'],
                     'pending':{},'writes':{},'rows':[],'old':[],'proposal':proposal}
        self.emit('rule_requested',name,{'proposal_id':result['proposal_id'],'action':result['action']})
        self._query('inspect',self.compiler.namespace(name),HOST_MASK)
        return 202,self.public(result)

    @staticmethod
    def public(result: dict) -> dict:
        return {k:v for k,v in result.items() if k!='fingerprint'}

    def snapshot(self) -> dict:
        return {'enabled':True,'controller_epoch':self.epoch,'clinical_floor_confirmed':self.ready,
                'variant':self.compiler.settings['variant'],'busy':bool(self.active),
                'actions':[self.public(r) for r in self.results.values()],
                'events':list(self.events),'event_last_seq':self.event_seq}

    def fail(self, reason: str) -> None:
        job=self.active
        if not job:return
        if job['host']:
            job['result']['status']='failed'
            job['result']['error']=reason[:256]
        else:self.ready=False
        self.active=None;self.retry_after=self.clock()+2

    def _queue(self, kind: str, dpid: int, **kwargs: object) -> bool:
        job=self.active
        handle=self.adapter.prepare(kind,dpid,**kwargs)
        key=(dpid,handle.xid)
        if kind in ('barrier','stats'):
            job['pending'][key]={'dp':handle.dp,'kind':kind,'parts':0,'rows':[],'sent_at':self.clock()}
        else:job['writes'][key]=handle.dp
        sent=self.adapter.queue(handle)
        if not sent and self.active is job:self.fail('OpenFlow send failed')
        return sent and self.active is job

    def _query(self, phase: str, cookie: int, mask: int) -> None:
        job=self.active;job['phase']=phase;job['rows']=[];job['pending']={}
        self._batch('stats',cookie=cookie,mask=mask)

    def _batch(self,kind: str,**kwargs: object) -> None:
        """Register the entire batch before any queue call can cooperatively yield."""
        job=self.active
        handles=[self.adapter.prepare(kind,d,**kwargs) for d in self.compiler.fabric.switches]
        for h in handles:
            job['pending'][(h.dp.id,h.xid)]={'dp':h.dp,'kind':kind,'parts':0,'rows':[],'sent_at':self.clock()}
        for h in handles:
            if self.active is not job:return
            if not self.adapter.queue(h):
                if self.active is job:self.fail('OpenFlow send failed')
                return

    def _write_phase(self,phase: str,ops: list[tuple[str,Rule]]) -> None:
        job=self.active;job['phase']=phase;job['ops']=deque(ops);job['pending']={};job['barriers_sent']=False

    def tick(self) -> None:
        signature=tuple(sorted((d,id(dp)) for d,dp in self.adapter.connections().items()))
        if signature!=self.connection_signature:
            self.connection_signature=signature;self.ready=False
            if self.active:self.fail('Datapath connection changed; reconciliation required')
        if set(self.adapter.connections())!=set(self.compiler.fabric.switches):return
        if not self.active:
            if not self.ready and self.clock()>=self.retry_after:
                self.active={'id':uuid.uuid4().hex,'host':None,'rules':self.compiler.floor,
                    'deadline':self.clock()+self.compiler.settings['transaction_timeout_s'],
                    'pending':{},'writes':{},'rows':[]}
                self._write_phase('floor',[('add',r) for r in self.compiler.floor])
            else:return
        job=self.active
        if self.clock()>=job['deadline']:
            self.fail('Transaction deadline exceeded; any partial containment expires by hard timeout');return
        if any(self.clock()-p['sent_at']>=self.compiler.settings['reply_timeout_s']
               for p in job['pending'].values()):
            self.fail('OpenFlow acknowledgement/readback reply timed out');return
        if 'ops' not in job:return
        sent=0
        while job['ops'] and sent<self.compiler.settings['max_ops_per_tick'] and self.bucket.take(self.clock()):
            kind,rule=job['ops'].popleft()
            require(kind!='delete' or rule.priority in (40000,45000) and rule.cookie&FLOOR_MASK==ACTION_PREFIX,
                    'Refusing deletion outside containment namespace')
            if not self._queue(kind,rule.dpid,rule=rule):return
            sent+=1
        if not job['ops'] and not job['barriers_sent']:
            job['barriers_sent']=True
            self._batch('barrier')

    def reply(self,kind: str,dpid: int,xid: int,dp: object,rows: list[dict]|None=None,more: bool=False) -> bool:
        job=self.active
        if not job:return False
        key=(dpid,xid);pending=job['pending'].get(key)
        if not pending or pending['kind']!=kind or pending['dp'] is not dp:return False
        if self.clock()>=job['deadline']:
            self.fail('Late transaction reply after deadline');return True
        if self.clock()-pending['sent_at']>=self.compiler.settings['reply_timeout_s']:
            self.fail('Late acknowledgement/readback reply');return True
        if self.adapter.connections().get(dpid) is not dp:
            self.fail('Reply came from obsolete datapath');return True
        if kind=='stats':
            pending['parts']+=1
            if pending['parts']>self.compiler.settings['max_parts'] or len(pending['rows'])+len(rows or [])>self.compiler.settings['max_rows']:
                self.fail('Action readback exceeded resource bounds');return True
            for row in rows or []:
                match=json.dumps(row['match'],sort_keys=True)
                pending['rows'].append(Rule(dpid,row['cookie'],row['priority'],match,row['output'],row['hard_timeout']))
            if more:return True
            job['rows'].extend(pending['rows'])
            if len(job['rows'])>self.compiler.settings['max_rows']:
                self.fail('Action readback exceeded total row bound');return True
        del job['pending'][key]
        if job['pending']:return True
        if 'ops' in job:
            del job['ops']
            phase=job['phase']
            if phase=='floor':self._query('verify_floor',FLOOR_PREFIX,FLOOR_MASK)
            elif phase=='allows':self._write_phase('drops',[('add',r) for r in job['rules'] if r.priority==40000])
            elif phase=='drops':
                new={r.identity for r in job['rules']}
                self._write_phase('cleanup',[('delete',r) for r in job['old'] if r.identity not in new])
            elif phase=='cleanup':self._query('verify_action',self.compiler.namespace(job['host']),HOST_MASK)
            return True
        phase=job['phase']
        if phase=='inspect':
            if any(r.priority not in (40000,45000) or r.cookie&HOST_MASK!=self.compiler.namespace(job['host']) for r in job['rows']):
                self.fail('Unexpected rule in private containment namespace');return True
            job['old']=job['rows']
            if job['result']['action']=='RELEASE':self._write_phase('cleanup',[('delete',r) for r in job['old']])
            else:self._write_phase('allows',[('add',r) for r in job['rules'] if r.priority==45000])
        elif phase in ('verify_floor','verify_action'):
            expected=job['rules'];actual=job['rows']
            good={r.identity:r.hard_timeout for r in actual}
            if (len(good)!=len(expected) or any(good.get(r.identity)!=r.hard_timeout for r in expected)):
                self.fail('Switch readback does not match compiled rules');return True
            if phase=='verify_floor':self.ready=True
            else:
                job['result']['status']='confirmed'
                job['result']['confirmed_ns']=int(self.clock()*1e9)
                self.emit('released' if job['result']['action']=='RELEASE' else 'rule_installed',job['host'],
                          {'proposal_id':job['id'],'action':job['result']['action'],'readback_confirmed':True})
            self.active=None
        return True

    def error(self,dpid: int,xid: int,dp: object) -> None:
        job=self.active
        if not job or self.adapter.connections().get(dpid) is not dp:return
        key=(dpid,xid)
        if job['writes'].get(key) is dp or job['pending'].get(key,{}).get('dp') is dp:
            self.fail('Switch returned OpenFlow error')
