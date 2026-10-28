"""Ryu OF1.3 static-fabric forwarding and read-only bounded telemetry."""
from __future__ import annotations

from collections import Counter, deque
import json
import os
from pathlib import Path
import resource
import time
import uuid

from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, icmp, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from controller import action_api
from controller.core import (Fabric, NORMAL_PRIORITY, RuleBudget, StatsCache,
                             TokenBucket, flow_identity, ipv4_match, load_plan, load_settings)


class HospitalController(app_manager.RyuApp):
    """All controller mutation runs on eventlet handlers/green threads; no shared HTTP client."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        root = Path(__file__).resolve().parents[1]
        self.settings = load_settings(Path(os.environ.get(
            "HOSPITAL_CONTROLLER_CONFIG", str(root / "configs" / "controller.yaml"))))
        self.fabric = Fabric(load_plan(Path(os.environ.get(
            "HOSPITAL_TOPOLOGY_CONFIG", str(root / "configs" / "hospital.yaml")))))
        self.epoch = uuid.uuid4().hex
        self.datapaths = {}
        access = sorted({h["access_dpid"] for h in self.fabric.hosts.values()})
        self.polled = sorted(self.fabric.switches) if self.settings["poll_core"] else access
        self.cache = StatsCache(self.polled, self.settings)
        self.global_bucket = TokenBucket(self.settings["packet_in_rate"], self.settings["packet_in_burst"])
        self.source_buckets = {name: TokenBucket(self.settings["source_packet_in_rate"],
                                                self.settings["source_packet_in_burst"])
                               for name in self.fabric.hosts}
        self.global_guard_until = 0.0
        self.source_guard_until = {name: 0.0 for name in self.fabric.hosts}
        self.mod_bucket = TokenBucket(self.settings["flow_mod_rate"], self.settings["flow_mod_burst"])
        self.rule_budget = RuleBudget(list(self.fabric.switches),
                                      self.settings["normal_rule_limit_per_switch"])
        self.counts = Counter()
        self.observations = deque(maxlen=self.settings["observation_limit"])
        self.observation_seq = 0
        self.last_error = None
        self.started_ns = time.monotonic_ns()
        kwargs["wsgi"].register(TelemetryAPI, {"app": self})
        action_api.install(self, kwargs["wsgi"])
        self.monitor = hub.spawn(self._poll_loop)
        self.log("controller_started", epoch=self.epoch, expected_switches=len(self.fabric.switches),
                 polled_switches=len(self.polled), variant=(self.enforcer.compiler.settings["variant"]
                     if self.enforcer else "telemetry-only"))

    def log(self, check: str, **details: object) -> None:
        """Structured metadata only; never log packet payloads."""
        self.logger.info(json.dumps({"check": check, "timestamp_ns": time.monotonic_ns(), **details}))

    def send(self, dp: object, message: object) -> bool:
        """Bound eventlet queue backpressure; true means queued, not installed."""
        queued = False
        try:
            with hub.Timeout(self.settings["send_timeout_s"], False):
                queued = bool(dp.send_msg(message))
        except Exception as exc:
            self.last_error = {"error": str(exc)[:256], "timestamp_ns": time.monotonic_ns()}
        if not queued:
            self.counts["send_queue_failures"] += 1
            self.last_error = {"error": "OpenFlow send failed or timed out",
                               "dpid": f"{dp.id:016x}", "timestamp_ns": time.monotonic_ns()}
        return queued

    def close(self) -> None:
        """Stop the owned polling green thread during controller teardown."""
        hub.kill(self.monitor)
        hub.joinall([self.monitor])
        super().close()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev: object) -> None:
        dp = ev.msg.datapath
        if dp.id not in self.fabric.switches:
            self.counts["unknown_switches_rejected"] += 1
            return
        self.datapaths[dp.id] = dp
        if dp.id in self.polled:
            self.cache.register(dp.id)
        parser, ofp = dp.ofproto_parser, dp.ofproto
        # Full packets preserve first-packet forwarding when OVS has no buffers.
        # Software admission does not cap traffic reaching the Ryu TCP socket.
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.send(dp, parser.OFPFlowMod(datapath=dp, table_id=0, priority=0,
                                       match=parser.OFPMatch(), instructions=instructions))
        # Retain existing rules on reconnect; never delete externally installed clinical allows.
        self.log("switch_connected", dpid=f"{dp.id:016x}", switch=self.fabric.switches[dp.id])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev: object) -> None:
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and self.datapaths.get(dp.id) is dp:
            self.datapaths.pop(dp.id, None)
            self.cache.disconnect(dp.id)
            self.log("switch_disconnected", dpid=f"{dp.id:016x}")

    def _poll_loop(self) -> None:
        """Stagger access-switch requests, with at most one outstanding per switch."""
        while self.is_active:
            for dpid in self.polled:
                if self.enforcer:
                    try:
                        self.enforcer.tick()
                    except Exception as exc:
                        self.enforcer.fail(str(exc))
                        self.counts["action_runtime_errors"] += 1
                dp = self.datapaths.get(dpid)
                if dp:
                    request = dp.ofproto_parser.OFPFlowStatsRequest(dp, table_id=0)
                    dp.set_xid(request)
                    if self.cache.begin(dpid, request.xid, time.monotonic_ns()):
                        if self.send(dp, request):
                            self.counts["stats_requests"] += 1
                        elif self.datapaths.get(dpid) is dp:
                            self.cache.reject(dpid, request.xid, "Stats request send failed")
                hub.sleep(self.settings["poll_interval_s"] / len(self.polled))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply(self, ev: object) -> None:
        msg, rows = ev.msg, []
        if action_api.stats_reply(self, msg):
            return
        dp = msg.datapath
        if self.datapaths.get(dp.id) is not dp or dp.id not in self.polled:
            return
        # Parse at most limit+1 rows; the cache rejects oversized responses.
        for stat in msg.body[:self.settings["max_rows_per_switch"] + 1]:
            match = dict(stat.match.items())
            rows.append({"table_id": stat.table_id, "priority": stat.priority,
                         "cookie": f"0x{stat.cookie:x}", "match": match,
                         "packets": stat.packet_count, "bytes": stat.byte_count,
                         "duration_ns": stat.duration_sec * 1_000_000_000 + stat.duration_nsec,
                         "idle_timeout_s": stat.idle_timeout, "hard_timeout_s": stat.hard_timeout,
                         "ingress_source_host": self.fabric.source_for_row(dp.id, match)})
        final = self.cache.accept(dp.id, msg.xid, rows,
                                  bool(msg.flags & dp.ofproto.OFPMPF_REPLY_MORE),
                                  time.monotonic_ns())
        if final:
            self.counts["stats_polls_completed"] += 1

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def ofp_error(self, ev: object) -> None:
        msg = ev.msg
        if self.datapaths.get(msg.datapath.id) is not msg.datapath:
            return
        if self.enforcer:
            self.enforcer.error(msg.datapath.id, msg.xid, msg.datapath)
        self.counts["openflow_errors"] += 1
        self.last_error = {"dpid": f"{msg.datapath.id:016x}", "xid": msg.xid,
                           "type": msg.type, "code": msg.code,
                           "timestamp_ns": time.monotonic_ns()}
        self.cache.reject(msg.datapath.id, msg.xid, f"OpenFlow error {msg.type}/{msg.code}")
        self.log("openflow_error", **self.last_error)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def action_barrier(self, ev: object) -> None:
        msg = ev.msg
        if self.enforcer:
            self.enforcer.reply('barrier', msg.datapath.id, msg.xid, msg.datapath)

    def observe(self, dp: object, msg: object, host: dict, ip: object, l4: object) -> None:
        """Record source-ingress packet-ins separately from cumulative switch counters."""
        if len(self.observations) == self.observations.maxlen:
            self.counts["observations_evicted"] += 1
        self.observation_seq += 1
        self.observations.append({
            "seq": self.observation_seq, "timestamp_ns": time.monotonic_ns(),
            "host": host["name"], "role": host["role"], "dpid": f"{dp.id:016x}",
            "src": ip.src, "dst": ip.dst, "ip_proto": ip.proto,
            "src_port": getattr(l4, "src_port", None),
            "dst_port": getattr(l4, "dst_port", None), "wire_bytes": msg.total_len})

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev: object) -> None:
        msg = ev.msg
        dp = msg.datapath
        self.counts["packet_in_total"] += 1
        if self.datapaths.get(dp.id) is not dp:
            return
        now = time.monotonic()
        if now < self.global_guard_until or not self.global_bucket.take(now):
            if now >= self.global_guard_until:
                self.global_guard_until = now + self.settings["guard_cooldown_s"]
            self.counts["global_guard_drops"] += 1
            return
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if msg.buffer_id == ofp.OFP_NO_BUFFER and len(msg.data) < msg.total_len:
            self.counts["truncated_unbuffered_drops"] += 1
            return
        try:
            pkt = packet.Packet(msg.data[:256])
            eth = pkt.get_protocol(ethernet.ethernet)
            in_port = msg.match["in_port"]
            if not eth or not self.fabric.valid_source(dp.id, in_port, eth.src):
                self.counts["invalid_source_drops"] += 1
                return
            host = self.fabric.by_mac[eth.src]
            ingress = self.fabric.is_ingress(dp.id, in_port, eth.src)
            if ingress:
                source = host["name"]
                if (now < self.source_guard_until[source]
                        or not self.source_buckets[source].take(now)):
                    if now >= self.source_guard_until[source]:
                        self.source_guard_until[source] = now + self.settings["guard_cooldown_s"]
                    self.counts["source_guard_drops"] += 1
                    return
            match = None
            destination = None
            if eth.ethertype == 0x0806:
                a = pkt.get_protocol(arp.arp)
                if a and a.src_ip == host["address"] and a.src_mac == host["mac"] and a.opcode in (1, 2):
                    destination = self.fabric.by_ip.get(a.dst_ip)
                    match = {"in_port": in_port, "eth_type": 0x0806, "eth_src": eth.src,
                             "arp_op": a.opcode, "arp_spa": a.src_ip, "arp_tpa": a.dst_ip}
            elif eth.ethertype == 0x0800:
                ip = pkt.get_protocol(ipv4.ipv4)
                if not ip or ip.src != host["address"] or ip.offset or ip.flags & 1:
                    self.counts["invalid_or_fragmented_ipv4_drops"] += 1
                    return
                l4 = pkt.get_protocol(tcp.tcp) if ip.proto == 6 else (
                    pkt.get_protocol(udp.udp) if ip.proto == 17 else pkt.get_protocol(icmp.icmp))
                if ingress:
                    self.observe(dp, msg, host, ip, l4)
                destination = self.fabric.by_ip.get(ip.dst)
                if destination and eth.dst == destination["mac"]:
                    match = ipv4_match(in_port, eth.src, eth.dst, ip.src, ip.dst, ip.proto,
                                       getattr(l4, "src_port", None), getattr(l4, "dst_port", None),
                                       getattr(l4, "type", None), getattr(l4, "code", None))
                else:
                    destination = None
            if not destination or not match:
                self.counts["unknown_or_unsupported_drops"] += 1
                return
            out_port = self.fabric.ports[(dp.id, destination["mac"])]
            if out_port == in_port:
                self.counts["same_port_drops"] += 1
                return
            actions = [parser.OFPActionOutput(out_port)]
            cookie, hard_timeout = flow_identity(match, self.settings)
            lifetime = (self.settings["normal_hard_timeout_s"]
                        + self.settings["hard_timeout_jitter_s"] + self.settings["send_timeout_s"])
            install = False
            if not self.mod_bucket.take(now):
                self.counts["normal_flow_mod_rate_limited"] += 1
            elif not self.rule_budget.admit(dp.id, now, lifetime, match):
                self.counts["normal_rule_capacity_exhausted"] += 1
            else:
                install = True
            if install:
                instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                params = {"datapath": dp, "table_id": 0, "priority": NORMAL_PRIORITY,
                          "cookie": cookie, "match": parser.OFPMatch(**match),
                          "instructions": instructions,
                          "idle_timeout": self.settings["normal_idle_timeout_s"],
                          "hard_timeout": hard_timeout}
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    params["buffer_id"] = msg.buffer_id
                sent = self.send(dp, parser.OFPFlowMod(**params))
                if sent:
                    self.counts["normal_flow_mods"] += 1
                if sent and msg.buffer_id != ofp.OFP_NO_BUFFER:
                    return
            else:
                self.counts["normal_install_budget_exhausted"] += 1
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            if self.send(dp, parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions, data=data)):
                self.counts["packet_out_total"] += 1
        except (ValueError, KeyError, IndexError) as exc:
            self.counts["packet_parse_errors"] += 1
            self.last_error = {"error": str(exc)[:256], "timestamp_ns": time.monotonic_ns()}

    def stats(self) -> dict:
        """Copy complete poll snapshots and bounded observation metadata without yielding."""
        body = self.cache.view(time.monotonic_ns())
        body.update({"schema_version": 1, "controller_epoch": self.epoch,
                     "poll_interval_s": self.settings["poll_interval_s"],
                     "observations": list(self.observations),
                     "observation_first_seq": self.observations[0]["seq"] if self.observations else None,
                     "observation_last_seq": self.observation_seq,
                     "observations_evicted_total": self.counts["observations_evicted"],
                     "observation_guard_drops": {
                         key: self.counts[key] for key in ("source_guard_drops", "global_guard_drops")},
                     "observation_scope": "admitted_source_ingress_packet_ins"})
        return body

    def health(self) -> dict:
        """Expose snapshot quality and cumulative process resource counters."""
        stats = self.cache.view(time.monotonic_ns())
        connected = sorted(self.datapaths)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        recent_error = bool(self.last_error and (time.monotonic_ns() -
                            self.last_error["timestamp_ns"]) / 1e9 <=
                            self.settings["max_snapshot_age_s"])
        healthy = (len(connected) == len(self.fabric.switches) and stats["complete"]
                   and not recent_error)
        return {"schema_version": 1, "status": "ok" if healthy else "degraded",
                "controller_epoch": self.epoch, "timestamp_ns": time.monotonic_ns(),
                "started_ns": self.started_ns, "connected_dpids": [f"{d:016x}" for d in connected],
                "expected_switches": len(self.fabric.switches), "telemetry_complete": stats["complete"],
                "process_cpu_s": usage.ru_utime + usage.ru_stime,
                "process_max_rss_bytes": usage.ru_maxrss * 1024,
                "counts": dict(self.counts), "last_error": self.last_error,
                "global_guard_open": time.monotonic() < self.global_guard_until,
                "guard_open_sources": [name for name, until in self.source_guard_until.items()
                                       if time.monotonic() < until]}


class TelemetryAPI(ControllerBase):
    """Loopback read API; optional mutations are isolated in ActionAPI."""

    def __init__(self, req: object, link: object, data: dict, **config: object) -> None:
        super().__init__(req, link, data, **config)
        self.app = data["app"]

    @staticmethod
    def response(body: dict, status: int = 200) -> Response:
        return Response(status=status, content_type="application/json",
                        body=json.dumps(body).encode("utf-8"))

    @route("hospital_health", "/v1/health", methods=["GET"])
    def health(self, req: object, **kwargs: object) -> Response:
        body = self.app.health()
        return self.response(body, 200 if body["status"] == "ok" else 503)

    @route("hospital_stats", "/v1/stats", methods=["GET"])
    def stats(self, req: object, **kwargs: object) -> Response:
        return self.response(self.app.stats())

    @route("hospital_topology", "/v1/topology", methods=["GET"])
    def topology(self, req: object, **kwargs: object) -> Response:
        return self.response({"schema_version": 1, "topology": self.app.fabric.topology})
