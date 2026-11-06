"""What readers see. Every view keeps observed, administrator, inferred and external values apart, and an unknown
value is left out, so nothing looks known that is not. These shapes are the dashboard contract, documented in
docs/detection/asset-inventory.md, and they change only with SCHEMA_VERSION.
"""
import csv
import io

from . import changes, schema
from .schema import ADMIN, EXTERNAL, INFERRED, OBSERVED, SCHEMA_VERSION, iso

RELATED_WINDOW_MS = 24 * changes.HOUR
_FORMULA = ('=', '+', '-', '@', '\t', '\r')


def when(value):
    return iso(value) if value else None


def status_of(store, asset):
    """Conflicted takes priority for as long as anything about the identity is undecided."""
    return changes.CONFLICTED if asset['status'] != changes.MERGED and store.has_open_conflict(asset['asset_id']) else asset['status']


def summary(store, asset):
    attributes = {(a['name'], a['klass']): a['value'] for a in store.attributes(asset['asset_id'])}
    row = {'asset_id': asset['asset_id'], 'hostname': asset['hostname'], 'status': status_of(store, asset), 'asset_type': asset['asset_type'], 'platform': asset['platform'], 'identity_confidence': asset['confidence'],
           'last_seen': when(asset['last_ms']), 'last_inventory_update': when(asset['inventory_ms'])}
    for key, name in (('criticality', 'criticality'), ('os_name', 'os.name'), ('os_version', 'os.version')):
        klass = ADMIN if name == 'criticality' else OBSERVED
        if (name, klass) in attributes:
            row[key] = attributes[(name, klass)]
    return row


def by_class(store, asset_id):
    grouped = {OBSERVED: [], ADMIN: [], INFERRED: [], EXTERNAL: []}
    for item in store.attributes(asset_id):
        grouped[item['klass']].append({'name': item['name'], 'value': item['value'], 'source': item['source'], 'observed_at': when(item['observed_ms']), 'confidence': item['confidence']})
    return grouped


def item_row(item):
    return {**item['body'], 'class': item['klass'], 'source': item['source'], 'confidence': item['confidence'], 'first_seen': when(item['first_ms']), 'last_seen': when(item['last_ms']), 'present': bool(item['present']), 'removed_at': when(item['removed_ms'])}


def lease_row(lease, asset):
    current = asset['last_ms'] is not None and lease['end_ms'] >= (asset['inventory_ms'] or asset['last_ms'])
    return {'ip': lease['ip'], 'first_seen': when(lease['start_ms']), 'last_seen': when(lease['end_ms']), 'source': lease['source'], 'current': current}


def rel_row(rel):
    return {'id': rel['rel_id'], 'source': {'type': rel['src_type'], 'id': rel['src_id']}, 'type': rel['rel_type'], 'target': {'type': rel['dst_type'], 'id': rel['dst_id']}, 'first_seen': when(rel['first_ms']), 'last_seen': when(rel['last_ms']),
            'provenance': rel['source'], 'confidence': rel['confidence'], 'basis': 'inferred' if rel['klass'] == INFERRED else 'directly observed', 'count': rel['count']}


def change_row(change):
    return {'seq': change['seq'], 'at': when(change['at_ms']), 'asset_id': change['asset_id'], 'kind': change['kind'], 'category': change['category'], 'subject': change['subject'], 'before': change['before'], 'after': change['after'], 'class': change['klass'], 'source': change['source']}


def security_tools(store, asset_id, watch):
    services = store.items(asset_id, 'service')
    return [{'name': s['body'].get('display') or s['key'], 'service': s['key'], 'state': s['body'].get('state'), 'source': s['source'], 'last_seen': when(s['last_ms'])} for s in services if s['key'] in watch]


def exposure(store, asset_id):
    """Indicators only. An open port shows what is listening, and says nothing about what can reach it."""
    listeners = [i['body'] for i in store.items(asset_id, 'listener') if i['body'].get('scope') != 'loopback']
    return {'listeners_beyond_loopback': sorted(({'proto': x['proto'], 'port': x['port'], 'scope': x['scope'], 'process': x.get('process')} for x in listeners), key=lambda x: x['port'])}


def full(store, asset, watch):
    asset_id = asset['asset_id']
    grouped = by_class(store, asset_id)
    ids = store.identifiers(asset_id)
    leases = [lease_row(x, asset) for x in store.leases(asset_id)]
    return {'schema_version': SCHEMA_VERSION, **summary(store, asset), 'stored_status': asset['status'], 'merged_into': asset['merged_into'], 'merged_from': store.merged_from(asset_id),
            'lifecycle': {'first_seen': when(asset['first_ms']), 'last_seen': when(asset['last_ms']), 'last_inventory_update': when(asset['inventory_ms']), 'last_successful_collection': when(asset['collection_ms']), 'status_changed': when(asset['status_ms']), 'source_of_discovery': asset['source'], 'revision': asset['revision']},
            'identity': {'confidence': asset['confidence'], 'aliases': [{'name': i['value'], 'active': bool(i['active']), 'source': i['source'], 'first_seen': when(i['first_ms']), 'last_seen': when(i['last_ms'])} for i in ids if i['kind'] == 'hostname'],
                         'machine_identifiers': [{'kind': i['kind'], 'digest': i['value'], 'source': i['source'], 'first_seen': when(i['first_ms'])} for i in ids if i['kind'] not in ('hostname', 'mac')], 'open_conflicts': [c['conflict_id'] for c in store.conflicts('open', asset_id)]},
            'facts': grouped[OBSERVED], 'administrator': grouped[ADMIN], 'inferred': grouped[INFERRED], 'external_intelligence': grouped[EXTERNAL],
            'network': {'interfaces': [item_row(i) for i in store.items(asset_id, 'interface')], 'addresses': leases, 'physical_macs': [i['value'] for i in ids if i['kind'] == 'mac']},
            'security': {'tools': security_tools(store, asset_id, watch), 'exposure': exposure(store, asset_id), 'vulnerabilities': {'status': 'not_assessed', 'reason': 'no vulnerability source is connected, so none are claimed either way'}},
            'counts': {kind: store.count_items(asset_id, kind) for kind in ('software', 'service', 'local_account', 'observed_user', 'process', 'listener', 'interface')}}


def document(store, asset, watch, now):
    """The record in siem-assets-current, which future detection rules and the dashboard read. A small summary:
    lists of programs and accounts stay behind the analyst socket."""
    asset_id = asset['asset_id']
    attributes = {(a['name'], a['klass']): a for a in store.attributes(asset_id)}
    doc = {'schema_version': SCHEMA_VERSION, 'asset_id': asset_id, 'hostname': asset['hostname'], 'aliases': sorted(i['value'] for i in store.identifiers(asset_id) if i['kind'] == 'hostname' and i['active']), 'asset_type': asset['asset_type'], 'platform': asset['platform'],
           'status': status_of(store, asset), 'identity_confidence': asset['confidence'], 'merged_into': asset['merged_into'], 'ips': sorted({x['ip'] for x in store.leases(asset_id) if x['end_ms'] >= (asset['inventory_ms'] or asset['last_ms'] or 0)}), 'security_tools': sorted(t['service'] for t in security_tools(store, asset_id, watch)),
           'first_seen': when(asset['first_ms']), 'last_seen': when(asset['last_ms']), 'last_inventory_update': when(asset['inventory_ms']), 'last_successful_collection': when(asset['collection_ms']), 'discovery_source': asset['source'], 'updated_at': when(now), 'open_conflicts': len(store.conflicts('open', asset_id)),
           'vulnerability_status': 'not_assessed', 'counts': {k: store.count_items(asset_id, k) for k in ('software', 'service', 'listener')}}
    for name in schema.METADATA:
        if (name, ADMIN) in attributes:
            doc[name] = attributes[(name, ADMIN)]['value']
    system = {k: attributes[(f'os.{k}', OBSERVED)]['value'] for k in ('name', 'version', 'build', 'arch') if (f'os.{k}', OBSERVED) in attributes}
    if system:
        doc['os'] = system
    return {k: v for k, v in doc.items() if v not in (None, '', [])}


def relationships(store, asset_id):
    """Stored links, plus what the inventory lists hold, in one shape."""
    rows = [rel_row(r) for r in store.relationships(asset_id)]
    for kind, name in (('software', 'has_software'), ('service', 'runs_service')):
        for item in store.items(asset_id, kind):
            rows.append({'id': f'{asset_id}/{kind}/{item["key"]}', 'source': {'type': 'asset', 'id': asset_id}, 'type': name, 'target': {'type': kind, 'id': item['key']}, 'first_seen': when(item['first_ms']), 'last_seen': when(item['last_ms']), 'provenance': item['source'], 'confidence': item['confidence'], 'basis': 'directly observed', 'count': 1})
    owner = store.attribute(asset_id, 'owner', ADMIN)
    if owner is not None:
        rows.append({'id': f'{asset_id}/owner', 'source': {'type': 'asset', 'id': asset_id}, 'type': 'assigned_to', 'target': {'type': 'owner', 'id': owner}, 'provenance': 'administrator', 'confidence': schema.HIGH, 'basis': 'stated by an administrator', 'count': 1})
    return rows


def export_csv(store):
    """The asset CSV that D8 asks for. A cell that a spreadsheet would run as a formula is neutralised."""
    columns = ('asset_id', 'hostname', 'status', 'asset_type', 'platform', 'criticality', 'os_name', 'os_version', 'identity_confidence', 'last_seen')
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerow(columns)
    for asset in store.assets():
        row = summary(store, asset)
        writer.writerow([("'" + str(row.get(c, ''))) if str(row.get(c, '')).startswith(_FORMULA) else row.get(c, '') for c in columns])
    return buffer.getvalue()
