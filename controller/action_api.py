"""Opt-in authenticated mutation API and actual Ryu OpenFlow adapter."""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import os
from pathlib import Path

from ryu.app.wsgi import ControllerBase, Response, route

from controller.enforcement import ACTION_PREFIX, FLOOR_MASK, Compiler, FULL_MASK, Transactions, load_enforcement
from decision.detection import load_detection_config


@dataclass
class Prepared:
    dp: object
    xid: int
    message: object


class RyuAdapter:
    def __init__(self, app: object) -> None:
        self.app=app

    def connections(self) -> dict:
        return dict(self.app.datapaths)

    def prepare(self,kind: str,dpid: int,**kwargs: object) -> Prepared:
        dp=self.app.datapaths[dpid];p=dp.ofproto_parser;o=dp.ofproto
        if kind in ('add','delete'):
            r=kwargs['rule']
            if kind=='delete' and (r.priority not in (40000,45000) or r.cookie&FLOOR_MASK!=ACTION_PREFIX):
                raise ValueError('Refusing deletion of non-containment rule')
            instructions=[] if r.output is None else [p.OFPInstructionActions(
                o.OFPIT_APPLY_ACTIONS,[p.OFPActionOutput(r.output)])]
            if kind=='add':
                msg=p.OFPFlowMod(datapath=dp,cookie=r.cookie,table_id=0,
                    priority=r.priority,match=p.OFPMatch(**r.match),instructions=instructions,
                    hard_timeout=r.hard_timeout,idle_timeout=0)
            else:
                msg=p.OFPFlowMod(datapath=dp,cookie=r.cookie,cookie_mask=FULL_MASK,
                    command=o.OFPFC_DELETE_STRICT,table_id=0,priority=r.priority,
                    match=p.OFPMatch(**r.match),out_port=o.OFPP_ANY,out_group=o.OFPG_ANY)
        elif kind=='barrier':msg=p.OFPBarrierRequest(dp)
        elif kind=='stats':msg=p.OFPFlowStatsRequest(dp,table_id=0,cookie=kwargs['cookie'],cookie_mask=kwargs['mask'])
        else:raise ValueError('Unknown OpenFlow adapter operation')
        dp.set_xid(msg)
        return Prepared(dp,msg.xid,msg)

    def queue(self,handle: Prepared) -> bool:
        return self.app.send(handle.dp,handle.message)


def install(app: object,wsgi: object) -> None:
    """No new critical floor or mutation capability unless explicitly enabled."""
    app.enforcer=None
    app.action_token=os.environ.get('HOSPITAL_ACTION_TOKEN','')
    enabled=os.environ.get('HOSPITAL_ENABLE_ACTIONS')=='1'
    if enabled:
        if not 32<=len(app.action_token)<=256 or not app.action_token.isascii() or '\n' in app.action_token or '\r' in app.action_token:
            raise ValueError('Enabled action API requires a 32..256 character secret token')
        root=Path(__file__).resolve().parents[1]
        settings=load_enforcement(Path(os.environ.get('HOSPITAL_ENFORCEMENT_CONFIG', str(root/'configs'/'enforcement.yaml'))),app.fabric)
        policy=load_detection_config(Path(os.environ.get('HOSPITAL_POLICY_CONFIG', str(root/'configs'/'detection.yaml'))),app.fabric)
        app.enforcer=Transactions(Compiler(app.fabric,settings,policy),RyuAdapter(app),app.epoch)
    wsgi.register(ActionAPI,{'app':app})


def stats_reply(app: object,msg: object) -> bool:
    """Pass only bounded action requests to the coordinator, separate from telemetry XIDs."""
    actor=app.enforcer
    if actor is None or actor.active is None or (msg.datapath.id,msg.xid) not in actor.active['pending']:
        return False
    limit=actor.compiler.settings['max_rows']
    rows=[]
    for stat in msg.body[:limit+1]:
        output=None
        for instruction in stat.instructions:
            if instruction.type!=msg.datapath.ofproto.OFPIT_APPLY_ACTIONS:
                output=-1;break
            if len(instruction.actions)>1:
                output=-1;break
            for action in instruction.actions:
                if action.type!=msg.datapath.ofproto.OFPAT_OUTPUT:
                    output=-1;break
                output=action.port
        if stat.table_id!=0:output=-1
        rows.append({'cookie':stat.cookie,'priority':stat.priority,'match':dict(stat.match.items()),
                     'output':output,'hard_timeout':stat.hard_timeout,'table_id':stat.table_id})
    return actor.reply('stats',msg.datapath.id,msg.xid,msg.datapath,rows,
                       bool(msg.flags&msg.datapath.ofproto.OFPMPF_REPLY_MORE))


class ActionAPI(ControllerBase):
    def __init__(self,req: object,link: object,data: dict,**config: object) -> None:
        super().__init__(req,link,data,**config)
        self.app=data['app']

    @staticmethod
    def response(body: dict,status: int=200) -> Response:
        return Response(status=status,content_type='application/json',body=json.dumps(body).encode())

    @route('hospital_action_status','/v1/actions',methods=['GET'])
    def status(self,req: object,**kwargs: object) -> Response:
        if self.app.enforcer is None:
            return self.response({'enabled':False,'clinical_floor_confirmed':False,
                                  'variant':'telemetry-only','actions':[],'events':[]})
        return self.response(self.app.enforcer.snapshot())

    @route('hospital_action_submit','/v1/actions',methods=['POST'])
    def submit(self,req: object,**kwargs: object) -> Response:
        if self.app.enforcer is None:return self.response({'error':'Actions are disabled'},503)
        supplied=req.headers.get('Authorization','')
        if not supplied.isascii() or len(supplied)>263 or not hmac.compare_digest(supplied,'Bearer '+self.app.action_token):
            return self.response({'error':'Invalid action authorization'},401)
        if type(req.content_length) is not int or not 0<req.content_length<=16384:
            return self.response({'error':'Action body must be 1..16384 bytes'},413)
        if self.app.health()['status']!='ok':
            return self.response({'error':'Fresh connected telemetry is required'},503)
        try:
            proposal=json.loads(req.body)
            status,body=self.app.enforcer.submit(proposal)
            return self.response(body,status)
        except (ValueError,KeyError,TypeError) as exc:
            return self.response({'error':str(exc)[:256]},400)
