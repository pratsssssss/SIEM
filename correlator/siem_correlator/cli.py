"""Two commands: `run`, for the service, and everything else, for analysts, through the control socket.
See docs/detection/incident-management.md.
"""
import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

import yaml

from . import control, rules, service
from .store import Store

SOCKET = '/run/siem-correlator/control.sock'


def run(config_path):
    config = yaml.safe_load(Path(config_path).read_text(encoding='utf8'))
    login = json.loads(Path(config['opensearch']['login_file']).read_text())
    store = Store(config['state_file'])
    opensearch = service.OpenSearch(config['opensearch']['url'], config['opensearch']['ca_file'], login['user'], login['password'])
    kafka = service.Kafka(config['kafka']['bootstrap'], config['kafka']['topic'])
    work = service.Service(store, rules.load(config['rules_file']), opensearch, kafka, log=lambda text: print(text, flush=True), **(config.get('service') or {}))
    server = control.Server(config.get('socket', SOCKET), control.Actions(work), log=work.log)
    server.start()
    stopping = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.append(1))
    work.log(f'correlator started, {len(work.rules)} rules')
    work.serve(config.get('reports', []), stopping=lambda: bool(stopping))
    server.stop()
    kafka.close()
    store.close()
    work.log('correlator stopped')
    return 0


def show(reply):
    if not reply.get('ok'):
        print(f"refused: {reply.get('error')}", file=sys.stderr)
        return 1
    print(json.dumps(reply['result'], indent=1, default=str))
    return 0


def table(reply):
    if not reply.get('ok'):
        return show(reply)
    for row in reply['result']:
        print(f"{row['incident_id'][:12]}  {row['status']:<14} {row['severity']:<9} {row['confidence_level']:<7} {row['alerts']:>3} alerts  {row['last_seen'][:19]}  {row['title']}")
    print(f"{len(reply['result'])} incidents")
    return 0


def full_id(path, value):
    """Accepts the short form that `list` prints."""
    if len(value) == 32:
        return value
    reply = control.call(path, {'action': 'list', 'limit': 500})
    found = [i['incident_id'] for i in reply.get('result', []) if i['incident_id'].startswith(value)]
    return found[0] if len(found) == 1 else value


def main(argv=None):
    parser = argparse.ArgumentParser(prog='siem-incident')
    parser.add_argument('--socket', default=os.environ.get('SIEM_INCIDENT_SOCKET', SOCKET))
    commands = parser.add_subparsers(dest='command', required=True)
    sub = commands.add_parser('run', help='the service itself')
    sub.add_argument('--config', default='/home/linux/siem/config/correlator/correlator.yaml')
    sub = commands.add_parser('list')
    sub.add_argument('--status')
    sub.add_argument('--limit', type=int, default=50)
    for name in ('show', 'timeline'):
        commands.add_parser(name).add_argument('incident')
    sub = commands.add_parser('search')
    for name in ('host', 'user', 'ip', 'severity'):
        sub.add_argument(f'--{name}')
    sub = commands.add_parser('status')
    sub.add_argument('incident')
    sub.add_argument('state')
    sub.add_argument('--note')
    sub = commands.add_parser('note')
    sub.add_argument('incident')
    sub.add_argument('text')
    sub = commands.add_parser('audit')
    sub.add_argument('incident', nargs='?')
    commands.add_parser('audit-verify')
    commands.add_parser('rules')
    for name in ('rule-enable', 'rule-disable'):
        commands.add_parser(name).add_argument('rule')
    sub = commands.add_parser('replay')
    sub.add_argument('--hours', type=int, required=True)
    commands.add_parser('lag')
    commands.add_parser('quarantine')
    args = parser.parse_args(argv)
    if args.command == 'run':
        return run(args.config)
    path = args.socket
    try:
        if args.command == 'list':
            return table(control.call(path, {'action': 'list', 'status': args.status, 'limit': args.limit}))
        if args.command == 'search':
            return table(control.call(path, {'action': 'search', 'host': args.host, 'user': args.user, 'ip': args.ip, 'severity': args.severity}))
        if args.command in ('show', 'timeline'):
            return show(control.call(path, {'action': args.command, 'incident_id': full_id(path, args.incident)}))
        if args.command == 'status':
            return show(control.call(path, {'action': 'status', 'incident_id': full_id(path, args.incident), 'state': args.state, 'note': args.note}))
        if args.command == 'note':
            return show(control.call(path, {'action': 'note', 'incident_id': full_id(path, args.incident), 'text': args.text}))
        if args.command == 'audit':
            return show(control.call(path, {'action': 'audit', 'incident_id': full_id(path, args.incident) if args.incident else None}))
        if args.command == 'audit-verify':
            return show(control.call(path, {'action': 'verify'}))
        if args.command == 'rules':
            return show(control.call(path, {'action': 'rules'}))
        if args.command in ('rule-enable', 'rule-disable'):
            return show(control.call(path, {'action': 'rule', 'rule_id': args.rule, 'enabled': args.command == 'rule-enable'}))
        if args.command == 'replay':
            return show(control.call(path, {'action': 'replay', 'hours': args.hours}, timeout=300))
        if args.command == 'lag':
            return show(control.call(path, {'action': 'health'}))
        return show(control.call(path, {'action': 'quarantine'}))
    except (OSError, ValueError) as error:
        print(f'cannot reach the correlator: {type(error).__name__}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
