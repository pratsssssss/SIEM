"""Command line. Run as: python3 -m siem_enricher <command>. See docs/detection/enrichment.md."""
import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

import yaml

from . import feeds as feed_lib
from . import indicators as ind
from . import providers as provider_lib
from . import service
from .engine import Engine, Limits
from .store import Store
from .web import Web


def load_config(path):
    return yaml.safe_load(Path(path).read_text(encoding='utf8'))


def provider_keys(config):
    """A key comes from the owner-only key file, or from the environment. Never from a command line."""
    keys = {}
    path = config.get('key_file')
    if path and Path(path).exists():
        keys = json.loads(Path(path).read_text())
    for name in provider_lib.ALL:
        value = os.environ.get('SIEM_KEY_' + name.upper().replace('-', '_'))
        if value:
            keys[name] = value
    return keys


def build_providers(config):
    """A provider exists only if it is enabled in configuration, and has its key if it needs one."""
    keys = provider_keys(config)
    active = {}
    for name, settings in (config.get('providers') or {}).items():
        cls = provider_lib.ALL.get(name)
        if cls is None or not (settings or {}).get('enabled'):
            continue
        provider = cls(keys.get(name))
        for option in ('per_minute', 'per_day', 'quality'):
            if option in settings:
                setattr(provider, option, settings[option])
        if provider.configured():
            active[name] = provider
    return active


def build(config):
    store = Store(config['state_file'])
    feeds = [feed_lib.Feed(**entry) for entry in config.get('feeds', [])]
    feeds += feed_lib.owner_files(config.get('owner_feed_folder'))
    providers = build_providers(config)
    hosts = {__import__('urllib.parse').parse.urlsplit(f.url).hostname for f in feeds if f.url}
    hosts |= {p.host for p in providers.values()}
    if 'abusech' in providers:
        hosts.add('mb-api.abuse.ch')
    for template in (config.get('geo') or {}).get('files', {}).values():
        hosts.add(__import__('urllib.parse').parse.urlsplit(template).hostname)
    web = Web(hosts, timeout=config.get('timeout_seconds', 15))
    clock = lambda: int(time.time() * 1000)
    log = lambda text: print(text, flush=True)
    feed_set = feed_lib.Feeds(store, feeds, web, clock, log)
    geo = feed_lib.Geo(config['geo']['folder']) if config.get('geo') else None
    settings = config.get('limits') or {}
    engine = Engine(store, feed_set, geo, providers, web, Limits(**settings), clock, log=log)
    return store, engine, feed_set, geo, web


def worker(config, engine, store):
    login = json.loads(Path(config['opensearch']['login_file']).read_text())
    client = service.OpenSearch(config['opensearch']['url'], config['opensearch']['ca_file'], login['user'], login['password'])
    return service.Worker(store, engine, client, external=bool(engine.providers), **(config.get('worker') or {}))


def cmd_status(args, config, store, engine, feeds, geo, web):
    print(json.dumps({k: v for k, v in service.Worker(store, engine, None).health().items()}, indent=1))
    return 0


def cmd_providers(args, config, store, engine, feeds, geo, web):
    health = {h['provider']: h for h in store.provider_health()}
    keys = provider_keys(config)
    for name, cls in provider_lib.ALL.items():
        settings = (config.get('providers') or {}).get(name) or {}
        state = 'active' if name in engine.providers else 'off: not enabled' if not settings.get('enabled') else 'off: no key'
        row = health.get(name, {})
        print(f"{name:<18} {state:<18} kinds={','.join(cls.kinds):<24} key={'yes' if name in keys else 'no'} ok={row.get('ok', 0)} failed={row.get('failed', 0)}")
    return 0


def cmd_feeds(args, config, store, engine, feeds, geo, web):
    if args.action == 'purge':
        print(f'{store.purge_feed(args.name)} rows removed from {args.name}')
        return 0
    if args.action == 'list':
        for row in feeds.status():
            print(f"{row['feed']:<24} {row['kind']:<7} enabled={row['enabled']!s:<6} rows={row['rows']:<9} fresh={row['fresh']!s:<6} error={row['last_error'] or ''}")
        return 0
    chosen = [f for f in feeds.feeds if f.enabled and (not args.name or f.name == args.name)] if args.force or args.name else feeds.due()
    for feed in chosen:
        print(f'{feed.name}: {feeds.update(feed, force=args.force)}', flush=True)
    if geo and (args.force or args.name == 'geo' or geo.age_days() > 35):
        for name, template in config['geo']['files'].items():
            print(f'geo {name}: {feed_lib.update_geo(web, config["geo"]["folder"], name, template, engine.clock)}', flush=True)
    return 0


def cmd_cache(args, config, store, engine, feeds, geo, web):
    if args.action == 'stats':
        print(json.dumps({'providers': store.cache_stats(engine.clock()), 'counters': store.counters()}, indent=1))
    elif args.action == 'expire':
        print(f'{store.cache_clear(expired_before=engine.clock())} expired entries removed')
    else:
        print(f'{store.cache_clear(args.provider, args.value)} entries removed')
    return 0


def cmd_lookup(args, config, store, engine, feeds, geo, web):
    item = ind.guess(args.value)
    if item is None:
        print('not an IP address, domain, URL or SHA-256')
        return 1
    print(json.dumps(engine.lookup([item], external=args.external)[item.key], indent=1))
    return 0


def cmd_enrich(args, config, store, engine, feeds, geo, web):
    work = worker(config, engine, store)
    status, document = work.enrich_alert(args.alert_id)
    print(json.dumps({'status': status, 'summary': document['summary']}, indent=1))
    return 0


def cmd_backfill(args, config, store, engine, feeds, geo, web):
    """Local matching over history. --dry-run reads and counts, and writes and sends nothing."""
    work = worker(config, engine, store)
    now = engine.clock()
    start = now - args.hours * 3600000
    if args.what in ('events', 'both'):
        print('events', work.scan_events(start, now, write=not args.dry_run, max_events=args.max_events))
    if args.what in ('alerts', 'both'):
        if args.dry_run:
            hits = work.opensearch.search(service.ALERT_INDEX, {'size': 0, 'track_total_hits': True, 'query': {'range': {'detected_at': {'gte': start, 'lt': now, 'format': 'epoch_millis'}}}})
            print('alerts in range', hits['hits']['total']['value'], 'jobs already held', sum(store.job_counts().values()))
        else:
            print('new alert jobs', work.discover_alerts(start, now), 'done', work.run_jobs(limit=args.max_alerts))
    return 0


def cmd_run(args, config, store, engine, feeds, geo, web):
    work = worker(config, engine, store)
    stopping = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.append(1))
    print(f'enricher started: {len(feeds.feeds)} feeds, {len(engine.providers)} external providers', flush=True)
    service.serve(work, config.get('reports', []), stopping=lambda: bool(stopping))
    print('enricher stopped', flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='siem_enricher')
    parser.add_argument('--config', default=os.environ.get('SIEM_ENRICHER_CONFIG', '/home/linux/siem/config/enricher/enricher.yaml'))
    commands = parser.add_subparsers(dest='command', required=True)
    for name, function in (('status', cmd_status), ('providers', cmd_providers), ('run', cmd_run)):
        commands.add_parser(name).set_defaults(function=function)
    sub = commands.add_parser('feeds')
    sub.add_argument('action', choices=('list', 'update', 'purge'))
    sub.add_argument('--name')
    sub.add_argument('--force', action='store_true')
    sub.set_defaults(function=cmd_feeds)
    sub = commands.add_parser('cache')
    sub.add_argument('action', choices=('stats', 'expire', 'clear'))
    sub.add_argument('--provider')
    sub.add_argument('--value')
    sub.set_defaults(function=cmd_cache)
    sub = commands.add_parser('lookup')
    sub.add_argument('value')
    sub.add_argument('--external', action='store_true', help='also ask configured external providers')
    sub.set_defaults(function=cmd_lookup)
    sub = commands.add_parser('enrich-alert')
    sub.add_argument('alert_id')
    sub.set_defaults(function=cmd_enrich)
    sub = commands.add_parser('backfill')
    sub.add_argument('what', choices=('events', 'alerts', 'both'))
    sub.add_argument('--hours', type=int, required=True)
    sub.add_argument('--dry-run', action='store_true')
    sub.add_argument('--max-events', type=int, default=200000)
    sub.add_argument('--max-alerts', type=int, default=200)
    sub.set_defaults(function=cmd_backfill)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    store, engine, feeds, geo, web = build(config)
    try:
        return args.function(args, config, store, engine, feeds, geo, web)
    finally:
        store.close()


if __name__ == '__main__':
    sys.exit(main())
