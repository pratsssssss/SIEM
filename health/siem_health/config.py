"""Configuration. Every threshold is checked against bounds, so a typing mistake stops the service at start.

The rationale for each default is in docs/operations/pipeline-health.md.
"""
import copy
import os
import re
from urllib.parse import urlsplit

import yaml

STATE_FILE = '/home/linux/siem/data/health/health.db'
REPORT_ROOT = '/home/linux/siem/data/status'
# The Windows folder for status reports. The installed health.yaml sets it from config/wsl/site.env.
MONITOR = os.environ.get('SIEM_WINDOWS_MONITOR', '/home/linux/siem/data/windows-monitor')

DEFAULTS = {
    'state_file': STATE_FILE,
    'publish_report': f'{MONITOR}/health.json',
    'watchdog_report': f'{REPORT_ROOT}/health-watchdog/watchdog.json',
    'reports': {
        'detector': f'{REPORT_ROOT}/detector/detector.json',
        'enricher': f'{REPORT_ROOT}/enricher/enricher.json',
        'correlator': f'{REPORT_ROOT}/correlator/correlator.json',
        'asset': f'{REPORT_ROOT}/asset/asset.json',
        'path': f'{REPORT_ROOT}/path/path.json',
        'linux-agent': f'{REPORT_ROOT}/linux-agent/health.json',
        'kafka-expiry': '/home/linux/siem/data/monitor/kafka-expiry.json',
        'disk-guard': '/home/linux/siem/data/monitor/disk-guard.json',
        'windows-agent': f'{MONITOR}/windows-agent.json',
    },
    'endpoints': {
        'aggregator_metrics': 'http://127.0.0.1:9599/metrics',
        'linux_agent_metrics': 'http://127.0.0.1:9597/metrics',
        'verifier_metrics': 'http://127.0.0.1:9612/metrics',
        'kafka': '127.0.0.1:9092',
    },
    'opensearch': {
        'url': 'https://127.0.0.1:9200',
        'ca_file': '/home/linux/siem/config/health/opensearch-ca.pem',
        'login_file': '/home/linux/siem/config/health/opensearch-health.json',
    },
    'windows_disk_path': '/mnt/c',
    'kafka': {'raw_topic': 'siem-raw-logs', 'raw_group': 'siem-aggregator', 'alert_topic': 'siem-alerts', 'alert_group': 'siem-correlator', 'incident_topic': 'siem-incidents'},
    'schedule': {'cycle_seconds': 60, 'events_every_cycles': 3, 'slow_every_cycles': 15, 'publish_every_cycles': 5},
    'timeouts': {'http_seconds': 3, 'opensearch_seconds': 5, 'kafka_seconds': 3, 'systemctl_seconds': 5},
    'bounds': {'max_response_bytes': 2000000, 'max_report_bytes': 65536, 'max_series': 6000, 'sample_events': 200, 'sample_alerts': 20, 'ship_batch': 200, 'outbox_rows': 5000, 'cycle_budget_seconds': 30},
    'hysteresis': {'worsen_cycles': 2, 'improve_cycles': 3, 'persist_after_seconds': 300, 'flap_window_minutes': 30, 'flap_transitions': 6, 'flap_factor': 2},
    'time': {'gap_factor': 3, 'resume_grace_seconds': 300, 'skew_tolerance_seconds': 120},
    'freshness': {'service_report_seconds': 180, 'timer_report_seconds': 900, 'windows_report_seconds': 900, 'hang_seconds': 600, 'not_progressing_seconds': 600, 'event_sample_seconds': 600, 'after_outage_seconds': 600},
    'thresholds': {
        'watermark_degraded_seconds': 600, 'watermark_unhealthy_seconds': 1800,
        'lag_degraded_messages': 5000, 'lag_unhealthy_messages': 100000,
        'oldest_degraded_seconds': 300, 'oldest_unhealthy_seconds': 3600,
        'latency_degraded_seconds': 300, 'latency_unhealthy_seconds': 1800,
        'outbox_degraded': 500, 'path_queue_degraded': 200, 'path_oldest_degraded_seconds': 1800,
        'normalize_degraded_percent': 1, 'normalize_unhealthy_percent': 20, 'normalize_min_events': 20,
        'memory_degraded_percent': 10, 'memory_unhealthy_percent': 5,
        'swap_degraded_percent': 50, 'swap_unhealthy_percent': 90,
        'pressure_degraded_percent': 5, 'pressure_unhealthy_percent': 25, 'cpu_pressure_degraded_percent': 50,
        'windows_disk_degraded_gib': 30, 'windows_disk_unhealthy_gib': 20,
        'heap_degraded_percent': 85, 'heap_unhealthy_percent': 95,
        'opensearch_disk_degraded_percent': 15, 'opensearch_disk_unhealthy_percent': 5,
        'restart_loop_count': 3, 'restart_loop_minutes': 30,
    },
    'retention': {'samples_hours': 48, 'hourly_days': 30, 'transitions_days': 90, 'diagnostics_days': 7},
    'sources': [],
}

BOUNDS = {
    'schedule.cycle_seconds': (30, 600), 'schedule.events_every_cycles': (1, 30), 'schedule.slow_every_cycles': (1, 120), 'schedule.publish_every_cycles': (1, 60),
    'timeouts.http_seconds': (1, 10), 'timeouts.opensearch_seconds': (1, 15), 'timeouts.kafka_seconds': (1, 10), 'timeouts.systemctl_seconds': (1, 15),
    'bounds.max_response_bytes': (100000, 8000000), 'bounds.max_report_bytes': (4096, 1000000), 'bounds.max_series': (100, 50000), 'bounds.sample_events': (10, 1000),
    'bounds.sample_alerts': (1, 200), 'bounds.ship_batch': (10, 1000), 'bounds.outbox_rows': (500, 50000), 'bounds.cycle_budget_seconds': (5, 120),
    'hysteresis.worsen_cycles': (1, 10), 'hysteresis.improve_cycles': (1, 20), 'hysteresis.persist_after_seconds': (60, 3600), 'hysteresis.flap_window_minutes': (5, 240),
    'hysteresis.flap_transitions': (3, 50), 'hysteresis.flap_factor': (1, 5),
    'time.gap_factor': (2, 20), 'time.resume_grace_seconds': (60, 3600), 'time.skew_tolerance_seconds': (5, 3600),
    'freshness.service_report_seconds': (60, 3600), 'freshness.timer_report_seconds': (300, 7200), 'freshness.windows_report_seconds': (300, 7200), 'freshness.hang_seconds': (120, 7200),
    'freshness.not_progressing_seconds': (120, 7200), 'freshness.event_sample_seconds': (60, 7200), 'freshness.after_outage_seconds': (300, 3600),
    'retention.samples_hours': (6, 168), 'retention.hourly_days': (7, 90), 'retention.transitions_days': (30, 365), 'retention.diagnostics_days': (1, 30),
}
THRESHOLD_PAIRS = [('watermark_degraded_seconds', 'watermark_unhealthy_seconds'), ('lag_degraded_messages', 'lag_unhealthy_messages'), ('oldest_degraded_seconds', 'oldest_unhealthy_seconds'),
                   ('latency_degraded_seconds', 'latency_unhealthy_seconds'), ('normalize_degraded_percent', 'normalize_unhealthy_percent'), ('swap_degraded_percent', 'swap_unhealthy_percent'),
                   ('pressure_degraded_percent', 'pressure_unhealthy_percent'), ('heap_degraded_percent', 'heap_unhealthy_percent')]
FALLING_PAIRS = [('memory_unhealthy_percent', 'memory_degraded_percent'), ('windows_disk_unhealthy_gib', 'windows_disk_degraded_gib'), ('opensearch_disk_unhealthy_percent', 'opensearch_disk_degraded_percent')]
DATASET = re.compile(r'^(windows|linux)\.[a-z_]{1,32}$')


class ConfigError(ValueError):
    pass


def _merge(base, extra, trail=''):
    for key, value in (extra or {}).items():
        if key not in base:
            raise ConfigError(f'unknown setting {trail}{key}')
        if isinstance(base[key], dict):
            if not isinstance(value, dict):
                raise ConfigError(f'{trail}{key} must be a mapping')
            _merge(base[key], value, f'{trail}{key}.')
        else:
            base[key] = value


def _loopback(url):
    return urlsplit(url).hostname in ('127.0.0.1', '::1')


def validate(config):
    for dotted, (low, high) in BOUNDS.items():
        section, name = dotted.split('.')
        value = config[section][name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise ConfigError(f'{dotted} must be a number from {low} to {high}')
    for name, value in config['thresholds'].items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 or value > 10 ** 9:
            raise ConfigError(f'thresholds.{name} must be a positive number')
    limits = config['thresholds']
    for low, high in THRESHOLD_PAIRS + FALLING_PAIRS:
        if limits[low] >= limits[high]:
            raise ConfigError(f'{low} must be below {high}')
    if config['timeouts']['http_seconds'] >= config['schedule']['cycle_seconds']:
        raise ConfigError('a query timeout must be shorter than a cycle')
    if config['bounds']['cycle_budget_seconds'] >= config['schedule']['cycle_seconds']:
        raise ConfigError('the cycle budget must be shorter than a cycle')
    # Nothing here ever leaves the machine. A remote address is a mistake or an attack.
    for name in ('aggregator_metrics', 'linux_agent_metrics', 'verifier_metrics'):
        if not _loopback(config['endpoints'][name]):
            raise ConfigError(f'endpoints.{name} must be on loopback')
    if not _loopback(config['opensearch']['url']):
        raise ConfigError('opensearch.url must be on loopback')
    if config['endpoints']['kafka'].rsplit(':', 1)[0] not in ('127.0.0.1', '[::1]'):
        raise ConfigError('endpoints.kafka must be on loopback')
    seen = set()
    for source in config['sources']:
        if not isinstance(source, dict) or set(source) - {'dataset', 'quiet_minutes'} or not DATASET.match(str(source.get('dataset'))):
            raise ConfigError(f'bad source entry {source!r}')
        quiet = source.get('quiet_minutes')
        if quiet is not None and (isinstance(quiet, bool) or not isinstance(quiet, (int, float)) or not 1 <= quiet <= 10080):
            raise ConfigError(f"quiet_minutes for {source['dataset']} must be from 1 to 10080, or absent for a source that is normally silent")
        if source['dataset'] in seen:
            raise ConfigError(f"{source['dataset']} is listed twice")
        seen.add(source['dataset'])
    return config


def load(path):
    with open(path, encoding='utf-8') as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ConfigError('the configuration must be a mapping')
    config = copy.deepcopy(DEFAULTS)
    _merge(config, raw)
    return validate(config)


def build(extra=None):
    config = copy.deepcopy(DEFAULTS)
    _merge(config, extra or {})
    return validate(config)
