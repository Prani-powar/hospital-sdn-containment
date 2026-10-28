"""Benchmark-only OVS rules, separate from the dashboard's authenticated actor.

B2 intentionally has NO clinical exemption. Never import this into production
or use it to relax controller.enforcement's safety invariants.
"""
import ipaddress
import re
from experiments.agents import normal_peers
from topology.restriction_demo import route, ofctl


def address(host):
    return str(ipaddress.ip_interface(host['ip']).ip)


def static_rules(topology, services):
    hosts = {h['name']: h for h in topology['hosts']}
    rules = []
    # Same-segment traffic is allowed; cross-segment traffic requires explicit
    # normal-peer or clinical service exceptions. ARP uses the controller.
    for name, host in hosts.items():
        switch = host['switch']
        for other, target in hosts.items():
            if other == name or target['segment'] == host['segment']:
                continue
            rules.append((switch, f'priority=59000,ip,nw_src={address(host)},nw_dst={address(target)},actions=drop'))
        for peer in normal_peers(name, hosts):
            for src, dst, field in ((name, peer, 'dst'), (peer, name, 'src')):
                for bridge, port in route(topology, src, dst):
                    rules.append((bridge, f'priority=60000,udp,nw_src={address(hosts[src])},nw_dst={address(hosts[dst])},tp_{field}=20081,actions=output:{port}'))
    for service in services:
        for name in service['sources']:
            for src, dst, field in ((name, service['server'], 'dst'), (service['server'], name, 'src')):
                for bridge, port in route(topology, src, dst):
                    rules.append((bridge, f"priority=60000,udp,nw_src={address(hosts[src])},nw_dst={address(hosts[dst])},tp_{field}={service['udp_port']},actions=output:{port}"))
    return sorted(set(rules))


def blind_rules(topology, host, ttl):
    item = next(h for h in topology['hosts'] if h['name'] == host)
    return [(s['name'], f'priority=62000,ip,nw_{field}={address(item)},hard_timeout={ttl},actions=drop')
            for s in topology['switches'] for field in ('src','dst')]


class OwnedRules:
    def __init__(self, run_id, bridges):
        self.prefix = 0xE700000000000000 | (int(run_id[:8],16) << 16)
        self.bridges = set(bridges)
        self.sequence = 0

    def install(self, rules):
        installed = []
        batches = {}
        for bridge, body in rules:
            if bridge not in self.bridges:
                raise ValueError('Rule targets an unowned bridge')
            self.sequence += 1
            if self.sequence > 65535:
                raise ValueError('Experiment rule budget exceeded')
            cookie = self.prefix | self.sequence
            record = {'bridge': bridge, 'cookie': cookie, 'rule': body}
            batches.setdefault(bridge, []).append(record)
            installed.append(record)
        for bridge, records in batches.items():
            ofctl('add-flows', bridge, '-', stdin='\n'.join(
                f"cookie=0x{r['cookie']:x}," + r['rule'] for r in records)+'\n')
            rows = ofctl('dump-flows', bridge, f'cookie=0x{self.prefix:x}/0xffffffffffff0000')
            actual = {}
            for line in rows.splitlines():
                match = re.search(r'\bcookie=0x([0-9a-fA-F]+)\b', line)
                if match:
                    actual.setdefault(int(match.group(1),16),[]).append(line)
            for r in records:
                lines = actual.get(r['cookie'],[])
                if len(lines) != 1 or not self.matches(lines[0],r['rule']):
                    raise RuntimeError('Benchmark rule readback mismatch')
        return installed

    @staticmethod
    def matches(line, body):
        fields, actions = body.split(',actions=',1)
        tokens = fields.split(',')
        for token in tokens:
            if token == 'ip':
                if not re.search(r'[, ]ip[, ]', line): return False
            elif token == 'udp':
                if not re.search(r'[, ]udp[, ]', line): return False
            elif token not in line.split(' actions=')[0].replace(' ', '').split(','):
                return False
        return line.split('actions=',1)[-1].strip() == actions

    def cleanup(self):
        for bridge in sorted(self.bridges):
            ofctl('del-flows', bridge, f'cookie=0x{self.prefix:x}/0xffffffffffff0000')
