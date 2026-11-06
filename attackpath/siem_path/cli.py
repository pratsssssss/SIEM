"""`run` is the service. Everything else is for analysts, through the control socket.
See docs/detection/attack-paths.md.
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

SOCKET = '/run/siem-path/control.sock'
ASSET_SOCKET = '/run/siem-asset/control.sock'


def run(config_path):
    config = yaml.safe_load(Path(config_path).read_text(encoding='utf8'))
    login = json.loads(Path(config['opensearch']['login_file']).read_text())
    store = Store(config['state_file'])
    opensearch = service.OpenSearch(config['opensearch']['url'], config['opensearch']['ca_file'], login['user'], login['password'])
    work = service.Service(store, opensearch, config, ip_lookup=service.asset_socket_lookup(config.get('asset_socket', ASSET_SOCKET)), log=lambda text: print(text, flush=True))
    server = control.Server(config.get('socket', SOCKET), control.Actions(work), log=work.log)
    server.start()
    stopping = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.append(1))
    work.log('attack path service started')
    work.serve(config.get('reports', []), stopping=lambda: bool(stopping))
    server.stop()
    store.close()
    work.log('attack path service stopped')
    return 0


def show(reply):
    if not reply.get('ok'):
        print(f"refused: {reply.get('error')}", file=sys.stderr)
        return 1
    print(json.dumps(reply['result'], indent=1, default=str))
    return 0


def parser_for():
    parser = argparse.ArgumentParser(prog='siem-path')
    parser.add_argument('--socket', default=os.environ.get('SIEM_PATH_SOCKET', SOCKET))
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('run').add_argument('--config', default='/home/linux/siem/config/path/path.yaml')
    for name in ('status', 'health'):
        commands.add_parser(name)
    commands.add_parser('list').add_argument('--tier')
    commands.add_parser('search').add_argument('query')
    for name in ('show', 'graph', 'timeline', 'history', 'explain'):
        commands.add_parser(name).add_argument('path')
    sub = commands.add_parser('evidence')
    sub.add_argument('path')
    sub.add_argument('--edge')
    commands.add_parser('asset').add_argument('asset')
    commands.add_parser('incident').add_argument('incident')
    commands.add_parser('validate').add_argument('path', nargs='?')
    commands.add_parser('audit').add_argument('path', nargs='?')
    sub = commands.add_parser('note')
    sub.add_argument('path')
    sub.add_argument('text')
    sub = commands.add_parser('rebuild')
    sub.add_argument('path')
    sub.add_argument('--reason', required=True)
    sub = commands.add_parser('link-identities')
    sub.add_argument('a')
    sub.add_argument('b')
    sub.add_argument('--reason', required=True)
    return parser


def request_for(args):
    name = args.command
    if name in ('status', 'health'):
        return {'action': 'health'}
    if name == 'list':
        return {'action': 'list', 'tier': args.tier}
    if name == 'search':
        return {'action': 'search', 'query': args.query}
    if name in ('show', 'graph', 'timeline', 'history', 'explain', 'validate', 'audit'):
        return {'action': name, 'path': args.path}
    if name == 'evidence':
        return {'action': 'evidence', 'path': args.path, 'edge': args.edge}
    if name == 'asset':
        return {'action': 'asset', 'asset': args.asset}
    if name == 'incident':
        return {'action': 'incident', 'incident': args.incident}
    if name == 'note':
        return {'action': 'note', 'path': args.path, 'text': args.text}
    if name == 'rebuild':
        return {'action': 'rebuild', 'path': args.path, 'reason': args.reason}
    return {'action': 'link_identities', 'a': args.a, 'b': args.b, 'reason': args.reason}


def main(argv=None):
    args = parser_for().parse_args(argv)
    if args.command == 'run':
        return run(args.config)
    try:
        return show(control.call(args.socket, request_for(args)))
    except (OSError, ValueError) as error:
        print(f'cannot reach the attack path service: {type(error).__name__}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
