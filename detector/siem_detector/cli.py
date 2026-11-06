"""Command line. Run as: python3 -m siem_detector <command>. See docs/detection/detection-engine.md."""
import argparse
import json
import os
import signal
import sys
from pathlib import Path

import yaml

from . import alerts, runner
from .backends import KafkaPublisher, OpenSearch, Outbox
from .dsl_eval import matches
from .rules import CatalogError, load
from .state import State


def _config(path):
    return yaml.safe_load(Path(path).read_text(encoding='utf8'))


def _engine(config):
    login = json.loads(Path(config['opensearch']['login_file']).read_text())
    store = OpenSearch(config['opensearch']['url'], config['opensearch']['ca_file'], login['user'], login['password'])
    state = State(config['state_file'])
    settings = runner.Settings(**config.get('runner', {}))
    rules = load(config['rules_dir'], include_disabled=False)
    return runner.Engine(rules, store, state, settings), state, store, settings


def cmd_validate(args):
    try:
        rules = load(args.rules, attack_data=args.attack)
    except CatalogError as error:
        print(f'INVALID {error}')
        return 1
    print(f'{len(rules)} rules valid, {sum(r.enabled for r in rules)} enabled')
    return 0


def cmd_list(args):
    for rule in sorted(load(args.rules), key=lambda r: r.title):
        print(f"{'on ' if rule.enabled else 'off'} {rule.kind:<6} {rule.level:<13} {rule.confidence:<6} {rule.interval_seconds:>5}s  {rule.id}  {rule.title}")
    return 0


def cmd_show(args):
    found = [r for r in load(args.rules) if args.rule in (r.id, Path(r.path).stem)]
    if not found:
        print('no such rule')
        return 1
    print(json.dumps(found[0].query, indent=1))
    return 0


def _hits(docs):
    return [{'_id': f'fixture-{i}', '_index': 'fixture', '_source': doc} for i, doc in enumerate(docs)]


def _custom_fires(rule, docs):
    """Custom rules are judged on a whole scenario: the events that pass their query, in time order."""
    hits = [h for h in _hits(docs) if matches(rule.query, h['_source'])]
    hits.sort(key=lambda h: h['_source'].get('@timestamp', ''))
    return bool(rule.custom.detect(hits))


def cmd_test(args):
    """Runs every rule against its positive and negative fixtures, with no services."""
    failures = 0
    checked = 0
    fixtures = yaml.safe_load(Path(args.fixtures).read_text(encoding='utf8'))
    for rule in load(args.rules):
        name = Path(rule.path).stem
        fixture = fixtures.get(name, {})
        if not fixture.get('match') or not fixture.get('no_match'):
            print(f'FAIL {name}: needs both match and no_match')
            failures += 1
            continue
        for expected, key in ((True, 'match'), (False, 'no_match')):
            if rule.custom:
                for index, scenario in enumerate(fixture[key]):
                    checked += 1
                    if _custom_fires(rule, scenario) != expected:
                        print(f'FAIL {name}: {key}[{index}]')
                        failures += 1
                continue
            for index, doc in enumerate(fixture[key]):
                checked += 1
                if matches(rule.query, doc) != expected:
                    print(f'FAIL {name}: {key}[{index}]')
                    failures += 1
    print(f'{checked} fixtures checked, {failures} failed')
    return 1 if failures else 0


def cmd_once(args):
    config = _config(args.config)
    engine, state, store, _ = _engine(config)
    engine.run_due()
    kafka = KafkaPublisher(config['kafka']['bootstrap'], config['kafka']['topic'])
    outbox = Outbox(state, store, kafka)
    for _ in range(args.cycles):
        if not state.counts()['pending']:
            break
        print(outbox.cycle())
    print(json.dumps({k: v for k, v in engine.health().items() if k != 'rules'}))
    return 0


def cmd_rewind(args):
    """Re-reads history for a rule. Existing alert IDs are ignored, so this cannot duplicate."""
    config = _config(args.config)
    engine, state, *_ = _engine(config)
    for rule in engine.rules:
        if args.rule in ('all', rule.id):
            state.rule(rule.id, engine.clock(), 0)
            state.set_watermark(rule.id, engine.clock() - args.hours * 3600000)
            print(f'{rule.id} rewound {args.hours} h')
    return 0


def cmd_status(args):
    config = _config(args.config)
    engine, state, *_ = _engine(config)
    print(json.dumps(engine.health(), indent=1))
    return 0


def cmd_run(args):
    config = _config(args.config)
    engine, state, store, settings = _engine(config)
    kafka = KafkaPublisher(config['kafka']['bootstrap'], config['kafka']['topic'])
    outbox = Outbox(state, store, kafka, log=engine.log)
    stopping = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.append(1))
    engine.log(f'detector started, {len(engine.rules)} rules enabled')
    runner.serve(engine, outbox, settings, config.get('reports', []), stopping=lambda: bool(stopping))
    kafka.poll(10)
    state.close()
    engine.log('detector stopped')
    return 0


def main(argv=None):
    default_rules = os.environ.get('SIEM_RULES', 'rules')
    parser = argparse.ArgumentParser(prog='siem_detector')
    parser.add_argument('--config', default=os.environ.get('SIEM_DETECTOR_CONFIG', '/home/linux/siem/config/detector/detector.yaml'))
    parser.add_argument('--rules', default=default_rules)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('validate')
    check.add_argument('--attack', action='store_true', help='also check ATT&CK tags, which downloads MITRE data')
    check.set_defaults(function=cmd_validate)
    for name, function in (('list', cmd_list), ('run', cmd_run), ('status', cmd_status)):
        commands.add_parser(name).set_defaults(function=function)
    show = commands.add_parser('show')
    show.add_argument('rule')
    show.set_defaults(function=cmd_show)
    test = commands.add_parser('test')
    test.add_argument('--fixtures', default='tests/detection/fixtures.yml')
    test.set_defaults(function=cmd_test)
    once = commands.add_parser('once')
    once.add_argument('--cycles', type=int, default=5)
    once.set_defaults(function=cmd_once)
    rewind = commands.add_parser('rewind')
    rewind.add_argument('rule')
    rewind.add_argument('--hours', type=int, required=True)
    rewind.set_defaults(function=cmd_rewind)
    args = parser.parse_args(argv)
    return args.function(args)


if __name__ == '__main__':
    sys.exit(main())
