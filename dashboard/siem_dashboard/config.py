"""Settings. Paths are configuration, so the same code runs in the lab and on a dedicated server."""
import copy
import ipaddress
from urllib.parse import urlsplit

import yaml

DEFAULTS = {
    'listen': {'host': '127.0.0.1', 'port': 8443},
    'tls': {'certificate': '/home/linux/siem/config/dashboard/tls/dashboard.crt', 'key': '/home/linux/siem/config/dashboard/tls/dashboard.key'},
    'state_file': '/home/linux/siem/data/dashboard/dashboard.db',
    'static_dir': '/opt/siem-dashboard/static',
    'opensearch': {'url': 'https://127.0.0.1:9200', 'ca_file': '/home/linux/siem/config/dashboard/opensearch-ca.pem', 'login_file': '/home/linux/siem/config/dashboard/opensearch-dashboard.json', 'timeout_seconds': 8, 'query_timeout': '5s'},
    'sockets': {'incidents': '/run/siem-correlator/control.sock', 'assets': '/run/siem-asset/control.sock', 'paths': '/run/siem-path/control.sock', 'timeout_seconds': 10},
    'health': {'config': '/home/linux/siem/config/health/health.yaml', 'app': '/opt/siem-health/app'},
    'correlator_app': '/opt/siem-correlator/app',
    'session': {'idle_minutes': 30, 'absolute_hours': 8},
    'login': {'failures': 5, 'window_minutes': 15, 'lock_minutes': 15, 'global_failures': 20},
    'limits': {'requests_per_minute': 240, 'anonymous_per_minute': 60, 'max_body_bytes': 16384, 'max_connections': 32, 'page_size': 100, 'max_offset': 900, 'max_days': 30, 'cache_seconds': 20, 'overview_scan': 500},
    'evidence_recheck_hours': 24,
    'require_loopback': True,
}
BOUNDS = {
    'session.idle_minutes': (5, 120), 'session.absolute_hours': (1, 24), 'login.failures': (3, 10), 'login.window_minutes': (5, 120), 'login.lock_minutes': (5, 240), 'login.global_failures': (5, 100),
    'limits.requests_per_minute': (30, 1200), 'limits.anonymous_per_minute': (10, 300), 'limits.max_body_bytes': (2048, 65536), 'limits.max_connections': (4, 128), 'limits.page_size': (10, 200),
    'limits.max_offset': (100, 9000), 'limits.max_days': (1, 90), 'limits.cache_seconds': (0, 300), 'limits.overview_scan': (50, 2000), 'opensearch.timeout_seconds': (1, 30), 'sockets.timeout_seconds': (1, 30),
}


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


def validate(config):
    for dotted, (low, high) in BOUNDS.items():
        section, name = dotted.split('.')
        value = config[section][name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ConfigError(f'{dotted} must be a whole number from {low} to {high}')
    try:
        address = ipaddress.ip_address(config['listen']['host'])
    except ValueError as error:
        raise ConfigError('listen.host must be an address, not a name') from error
    # Exposure is a deliberate act. On a dedicated server the owner sets this to false and restricts the network first.
    if config['require_loopback'] and not address.is_loopback:
        raise ConfigError('listen.host is not loopback while require_loopback is true')
    if address.is_unspecified:
        raise ConfigError('listen.host may not be a wildcard address')
    if urlsplit(config['opensearch']['url']).hostname not in ('127.0.0.1', '::1'):
        raise ConfigError('opensearch.url must be on loopback')
    return config


def load(path):
    with open(path, encoding='utf-8') as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ConfigError('the configuration must be a mapping')
    return build(raw)


def build(extra=None):
    config = copy.deepcopy(DEFAULTS)
    _merge(config, extra or {})
    return validate(config)
