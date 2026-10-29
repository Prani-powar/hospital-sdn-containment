"""Finite lab-only traffic and in-memory infection-marker agents.

A marker receipt records simulated infection; it never executes remote code,
changes files outside the run logs, or persists after this process exits.
"""
import argparse
import hashlib
import ipaddress
import json
import random
import select
import socket
import time
from pathlib import Path

from topology.hospital import load_plan, require

MARKER_PORT = 20080
NORMAL_PORT = 20081


def normal_peers(host, hosts):
    role = hosts[host]['role']
    names = {'admin': ['dns_ad'], 'guest': ['dns_ad'],
             'clinical': ['ehr', 'dns_ad'], 'critical_server': ['dns_ad'],
             'iomt': ['central_mon'] if host.startswith('monitor') else
                     ['pacs'] if host.startswith('imaging') else ['ehr'],
             'vendor': ['pacs', 'imaging1']}[role]
    return [n for n in names if n in hosts and n != host]


def run(args):
    hosts = {h['name']: h for h in load_plan(args.topology)['hosts']}
    require(args.host in hosts and args.source in hosts, 'Unknown experiment host')
    require(0 < args.rate <= 20 and 1 <= args.duration <= 150, 'Unbounded agent load')
    require(0 <= args.attack_after < args.duration, 'Invalid activation time')
    require(len(args.run_id) == 32 and all(c in '0123456789abcdef' for c in args.run_id), 'Invalid run id')
    ips = {n: str(ipaddress.ip_interface(h['ip']).ip) for n, h in hosts.items()}
    reverse = {ip: n for n, ip in ips.items()}
    derived = int.from_bytes(hashlib.sha256(f'{args.seed}:{args.host}'.encode()).digest()[:8], 'big')
    rng = random.Random(derived)
    peers = [n for n in hosts if n != args.host]
    rng.shuffle(peers)
    if args.scenario == 'S3':
        peers.sort(key=lambda n: n not in ('pacs', 'imaging1', 'ehr'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as marker, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as normal:
        def emit(stage, **details):
            row = dict(run_id=args.run_id, timestamp_ns=time.monotonic_ns(), stage=stage,
                       host=args.host, details=details)
            stream.write(json.dumps(row) + '\n'); stream.flush()
        marker.bind((ips[args.host], MARKER_PORT))
        normal.bind((ips[args.host], NORMAL_PORT))
        marker.setblocking(False); normal.setblocking(False)
        start = time.monotonic()
        infected = False
        attack_next = normal_next = start
        sent = 0
        emit('agent_ready', role=hosts[args.host]['role'], seed=args.seed)
        while time.monotonic() - start < args.duration:
            now = time.monotonic()
            if not infected and not getattr(args, 'normal_only', False) and args.host == args.source and now - start >= args.attack_after:
                infected = True
                emit('infection_marker', source='scenario_seed', synthetic=True)
            if infected and now >= attack_next:
                target = peers[sent % len(peers)]
                # Alternating marker and varying destination ports gives measurable
                # contacts/ports without hidden out-of-band propagation.
                port = MARKER_PORT if sent % 2 == 0 else 21000 + sent % 1000
                if sent % 2 == 0:
                    target = peers[(sent // 2) % len(peers)]
                payload = json.dumps({'run_id': args.run_id, 'kind': 'marker'}).encode()
                marker.sendto(payload, (ips[target], port))
                emit('attack_send', destination=target, port=port, sequence=sent)
                sent += 1
                attack_next = now + 1 / args.rate
            if now >= normal_next:
                allowed = normal_peers(args.host, hosts)
                if allowed:
                    target = rng.choice(allowed)
                    normal.sendto(b'normal-request', (ips[target], NORMAL_PORT))
                    emit('normal_send', destination=target, port=NORMAL_PORT)
                normal_next = now + rng.uniform(.8, 1.2)
            readable, _, _ = select.select([marker, normal], [], [], .02)
            for sock in readable:
                payload, address = sock.recvfrom(512)
                source = reverse.get(address[0])
                if source is None or address[1] not in (MARKER_PORT, NORMAL_PORT):
                    continue
                if sock is normal:
                    if payload == b'normal-request':
                        normal.sendto(b'normal-reply', address)
                    elif payload == b'normal-reply':
                        emit('normal_reply', source=source)
                else:
                    try:
                        value = json.loads(payload)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if value != {'run_id': args.run_id, 'kind': 'marker'}:
                        continue
                    emit('marker_received', source=source)
                    if not infected:
                        infected = True
                        emit('infection_marker', source=source, synthetic=True)
            # A scenario has no exploit or process creation on the receiver.
        emit('agent_finished', attack_packets=sent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--normal-only', action='store_true', help='Disable seed activation; collect controlled normal traffic')
    p.add_argument('--topology', type=Path, required=True)
    p.add_argument('--host', required=True); p.add_argument('--source', required=True)
    p.add_argument('--run-id', required=True); p.add_argument('--seed', type=int, required=True)
    p.add_argument('--scenario', choices=('S1','S2','S3'), required=True)
    p.add_argument('--rate', type=float, required=True)
    p.add_argument('--duration', type=float, required=True)
    p.add_argument('--attack-after', type=float, required=True)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args())

if __name__ == '__main__':
    main()
