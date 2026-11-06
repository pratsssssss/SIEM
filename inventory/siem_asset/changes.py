"""What a change means, and when an asset moves through its life. Pure functions, so each rule can be tested.

Routine changes are recorded and nothing more. Notable changes are recorded for review. Security changes also
raise the service's health to WARN until a person acknowledges them. None of them creates an alert or touches
an incident: a suspicious change is a lead, not a finding.
"""
from dataclasses import dataclass

ROUTINE, NOTABLE, SECURITY = 'routine', 'notable', 'security'
NEW, ACTIVE, STALE, RETIRED, REAPPEARED, MERGED, DECLARED, CONFLICTED = 'new', 'active', 'stale', 'retired', 'reappeared', 'merged', 'declared', 'conflicted'
DAY = 86400000
HOUR = 3600000


@dataclass
class Change:
    kind: str
    category: str
    subject: str = None
    before: object = None
    after: object = None


def _auto(body):
    return (body.get('start') or '').startswith('auto')


def services(old, new, watch):
    for key in sorted(new.keys() - old.keys()):
        yield Change('service_added', SECURITY if _auto(new[key]) or key in watch else NOTABLE, key, None, new[key].get('binary'))
    for key in sorted(old.keys() - new.keys()):
        yield Change('service_removed', SECURITY if key in watch else NOTABLE, key, old[key].get('binary'), None)
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        if before.get('binary') and after.get('binary') and before['binary'] != after['binary']:
            yield Change('service_binary_changed', SECURITY, key, before['binary'], after['binary'])
        if before.get('start') != after.get('start') and before.get('start') and after.get('start'):
            yield Change('service_start_changed', SECURITY if key in watch else ROUTINE, key, before['start'], after['start'])
        if key in watch and before.get('state') == 'running' and after.get('state') != 'running':
            yield Change('security_service_stopped', SECURITY, key, 'running', after.get('state'))


def software(old, new):
    for key in sorted(new.keys() - old.keys()):
        yield Change('software_installed', NOTABLE, new[key].get('name'), None, new[key].get('version'))
    for key in sorted(old.keys() - new.keys()):
        yield Change('software_removed', NOTABLE, old[key].get('name'), old[key].get('version'), None)
    for key in sorted(old.keys() & new.keys()):
        if old[key].get('version') != new[key].get('version'):
            yield Change('software_version_changed', ROUTINE, new[key].get('name'), old[key].get('version'), new[key].get('version'))


def users(old, new):
    for key in sorted(new.keys() - old.keys()):
        yield Change('local_account_added', SECURITY, new[key].get('name'), None, 'admin' if new[key].get('local_admin') else 'standard')
    for key in sorted(old.keys() - new.keys()):
        yield Change('local_account_removed', NOTABLE, old[key].get('name'))
    for key in sorted(old.keys() & new.keys()):
        if new[key].get('local_admin') and not old[key].get('local_admin'):
            yield Change('local_admin_granted', SECURITY, new[key].get('name'))
        if old[key].get('local_admin') and new[key].get('local_admin') is False:
            yield Change('local_admin_removed', NOTABLE, new[key].get('name'))
        if old[key].get('enabled') is False and new[key].get('enabled'):
            yield Change('local_account_enabled', SECURITY, new[key].get('name'))


def listeners(old, new):
    for key in sorted(new.keys() - old.keys()):
        yield Change('listener_opened', ROUTINE if new[key].get('scope') == 'loopback' else SECURITY, key, None, new[key].get('process'))
    for key in sorted(old.keys() - new.keys()):
        yield Change('listener_closed', ROUTINE, key, old[key].get('process'), None)


def security_state(name, before, after):
    """Weakening a control matters. Strengthening one is worth a line only."""
    weaker = {'defender_service': before is True and after is False, 'defender_realtime': before is True and after is False, 'rdp_enabled': before is False and after is True,
              'firewall_profiles_enabled': isinstance(before, int) and isinstance(after, int) and after < before}.get(name, False)
    return Change('security_control_weakened' if weaker else 'security_state_changed', SECURITY if weaker else ROUTINE, name, before, after)


def os_change(name, before, after):
    return Change('os_changed', NOTABLE if name in ('version', 'build', 'name') else ROUTINE, name, before, after)


def admin_change(name, before, after):
    return Change(f'{name}_changed', SECURITY if name == 'criticality' else NOTABLE, name, before, after)


@dataclass
class Lifecycle:
    new_hours: int = 72
    stale_days: int = 14

    @classmethod
    def load(cls, values):
        return cls(**{k: v for k, v in (values or {}).items() if k in cls.__dataclass_fields__})

    def tick(self, asset, now):
        """(status, change) if time alone moves this asset. Nothing is ever deleted for going quiet."""
        status, first, last = asset['status'], asset['first_ms'], asset['last_ms']
        if status in (NEW, ACTIVE) and last is not None and now - last > self.stale_days * DAY:
            return STALE, Change('asset_stale', NOTABLE, None, status, STALE)
        if status == NEW and first is not None and now - first > self.new_hours * HOUR:
            return ACTIVE, Change('asset_active', ROUTINE, None, NEW, ACTIVE)
        return None


def seen_again(status):
    """(status, change) when a report arrives for an asset that was out of service or quiet."""
    if status == STALE:
        return ACTIVE, Change('asset_returned', NOTABLE, None, STALE, ACTIVE)
    if status == RETIRED:
        return REAPPEARED, Change('retired_asset_seen', SECURITY, None, RETIRED, REAPPEARED)
    if status == DECLARED:
        return NEW, Change('declared_asset_seen', ROUTINE, None, DECLARED, NEW)
    return None
