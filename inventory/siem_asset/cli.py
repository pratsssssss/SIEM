"""`run` is the service. Everything else is for analysts and administrators, through the control socket.
See docs/detection/asset-inventory.md.
"""
import argparse
import json
import os
import signal
import sys
from pathlib import Path

import yaml

from . import control, service
from .store import Store

SOCKET = '/run/siem-asset/control.sock'


def run(config_path):
    config = yaml.safe_load(Path(config_path).read_text(encoding='utf8'))
    login = json.loads(Path(config['opensearch']['login_file']).read_text())
    store = Store(config['state_file'])
    opensearch = service.OpenSearch(config['opensearch']['url'], config['opensearch']['ca_file'], login['user'], login['password'])
    work = service.Service(store, opensearch, config, log=lambda text: print(text, flush=True))
    server = control.Server(config.get('socket', SOCKET), control.Actions(work), log=work.log)
    server.start()
    stopping = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.append(1))
    work.log('asset inventory started')
    work.serve(config.get('reports', []), stopping=lambda: bool(stopping))
    server.stop()
    store.close()
    work.log('asset inventory stopped')
    return 0


def show(reply):
    if not reply.get('ok'):
        print(f"refused: {reply.get('error')}", file=sys.stderr)
        return 1
    result = reply['result']
    print(result if isinstance(result, str) else json.dumps(result, indent=1, default=str), end='' if isinstance(result, str) else '\n')
    return 0


def parser_for():
    parser = argparse.ArgumentParser(prog='siem-asset')
    parser.add_argument('--socket', default=os.environ.get('SIEM_ASSET_SOCKET', SOCKET))
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('run').add_argument('--config', default='/home/linux/siem/config/asset/asset.yaml')
    for name in ('status', 'health', 'stale', 'export', 'validate'):
        commands.add_parser(name)
    sub = commands.add_parser('list')
    sub.add_argument('--status')
    sub.add_argument('--criticality')
    commands.add_parser('search').add_argument('query')
    for name in ('show', 'relationships', 'users'):
        commands.add_parser(name).add_argument('asset')
    sub = commands.add_parser('history')
    sub.add_argument('asset')
    sub.add_argument('--category', choices=('routine', 'notable', 'security'))
    for name in ('software', 'services'):
        sub = commands.add_parser(name)
        sub.add_argument('asset')
        sub.add_argument('--removed', action='store_true')
    sub = commands.add_parser('changes')
    sub.add_argument('--category', choices=('routine', 'notable', 'security'))
    sub.add_argument('--unreviewed', action='store_true')
    commands.add_parser('conflicts').add_argument('--all', action='store_true')
    sub = commands.add_parser('context')
    sub.add_argument('asset', nargs='?')
    sub.add_argument('--incident')
    sub.add_argument('--alert')
    sub.add_argument('--ip')
    sub.add_argument('--at')
    sub = commands.add_parser('ack')
    sub.add_argument('seq', type=int)
    sub.add_argument('--note')
    commands.add_parser('audit').add_argument('asset', nargs='?')
    sub = commands.add_parser('metadata')
    sub.add_argument('asset')
    sub.add_argument('name')
    sub.add_argument('value', nargs='?')
    sub.add_argument('--clear', action='store_true')
    sub = commands.add_parser('register')
    sub.add_argument('hostname')
    sub.add_argument('--type', default='unknown')
    sub.add_argument('--platform', default='unknown')
    for name in ('retire', 'reactivate'):
        sub = commands.add_parser(name)
        sub.add_argument('asset')
        sub.add_argument('--reason', required=True)
    sub = commands.add_parser('resolve')
    sub.add_argument('conflict')
    sub.add_argument('decision', choices=('merge', 'separate'))
    sub.add_argument('--keep')
    sub.add_argument('--reason', required=True)
    return parser


def request_for(args):
    """Each command to one request. A value is passed as data, and never reaches a shell or a query string."""
    name = args.command
    if name in ('status', 'health'):
        return {'action': 'health'}
    if name in ('stale', 'export', 'validate'):
        return {'action': name}
    if name == 'list':
        return {'action': 'list', 'status': args.status, 'criticality': args.criticality}
    if name == 'search':
        return {'action': 'search', 'query': args.query}
    if name in ('show', 'relationships', 'users'):
        return {'action': name, 'asset': args.asset}
    if name == 'history':
        return {'action': 'history', 'asset': args.asset, 'category': args.category}
    if name in ('software', 'services'):
        return {'action': name, 'asset': args.asset, 'removed': args.removed}
    if name == 'changes':
        return {'action': 'changes', 'category': args.category, 'unreviewed': args.unreviewed}
    if name == 'conflicts':
        return {'action': 'conflicts', 'all': args.all}
    if name == 'context':
        return {'action': 'context_of', 'asset': args.asset, 'incident': args.incident, 'alert': args.alert, 'ip': args.ip, 'at': args.at}
    if name == 'ack':
        return {'action': 'acknowledge', 'seq': args.seq, 'note': args.note}
    if name == 'audit':
        return {'action': 'audit', 'asset': args.asset}
    if name == 'metadata':
        return {'action': 'metadata', 'asset': args.asset, 'name': args.name, 'value': args.value, 'clear': args.clear}
    if name == 'register':
        return {'action': 'register', 'hostname': args.hostname, 'asset_type': args.type, 'platform': args.platform}
    if name in ('retire', 'reactivate'):
        return {'action': name, 'asset': args.asset, 'reason': args.reason}
    return {'action': 'resolve', 'conflict': args.conflict, 'decision': args.decision, 'keep': args.keep, 'reason': args.reason}


def main(argv=None):
    args = parser_for().parse_args(argv)
    if args.command == 'run':
        return run(args.config)
    try:
        return show(control.call(args.socket, request_for(args)))
    except (OSError, ValueError) as error:
        print(f'cannot reach the asset service: {type(error).__name__}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
