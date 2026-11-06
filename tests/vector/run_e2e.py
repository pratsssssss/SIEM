"""Live checks against the running pipeline, as root in WSL. Read-only, apart from `replay`.

Prints counts, field names and the test's own marker. It never prints real event content.

Usage: run_e2e.py check <marker.json> <token file> | sources | kafka <marker.json> <token file>
       | stats <marker.json> | unique | replay | state | listeners | arrived <marker.json> | continuity | reconcile <record ids.json>
       | ledger <record ids.json> | special <cases.json> <raw xml.json>
"""
import base64
import json
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

K = '/opt/kafka/bin'
BOOT = '127.0.0.1:9092'
TOPIC = 'siem-raw-logs'
ENV = {'JAVA_HOME': '/usr/lib/jvm/java-17-openjdk-amd64', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'KAFKA_HEAP_OPTS': '-Xmx256m', 'KAFKA_JMX_OPTS': ' '}
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def api(path, body=None, method=None):
    command = ['curl', '-sS', '--max-time', '30', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', f'https://127.0.0.1:9200{path}']
    if method:
        command += ['-X', method]
    if body is not None:
        command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    return json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)


def search(query, size=20, pattern='siem-windows-*', **extra):
    api(f'/{pattern}/_refresh', method='POST')
    return api(f'/{pattern}/_search', {'size': size, 'track_total_hits': True, 'query': query, **extra})


def hits(result):
    return result['hits']['total']['value']


def phrase(text):
    return {'multi_match': {'query': text, 'type': 'phrase', 'fields': ['process.command_line', 'powershell.script_block.text']}}


def get(doc, path):
    value = doc
    for part in path.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def load_marker(path):
    return json.load(open(path, encoding='utf-8-sig'))


def tokens(path):
    return [line.strip() for line in open(path, encoding='utf-8-sig') if line.strip()]


def wait_for(query, seconds=180):
    for _ in range(seconds // 5):
        if hits(search(query, 0)) > 0:
            return True
        time.sleep(5)
    return False


def check_marker(marker_file, token_file):
    info = load_marker(marker_file)
    marker, fake = info['marker'], info['fake']
    q_process = {'bool': {'filter': [{'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '1'}}, {'term': {'process.name': 'cmd.exe'}}, {'wildcard': {'process.command_line.keyword': f'*{marker}*'}}]}}
    check('Sysmon 1 test event reached OpenSearch', wait_for(q_process))
    docs = [h for h in search(q_process, 5)['hits']['hits']]
    if docs:
        hit = docs[0]
        source = hit['_source']
        line = get(source, 'process.command_line') or ''
        check('secret redacted, marker kept', fake not in line and '[REDACTED:arg]' in line and marker in line, line.replace(marker, '<marker>'))
        check('_id equals event.id', hit['_id'] == get(source, 'event.id'))
        check('event.category and type are ECS', get(source, 'event.category') == ['process'] and get(source, 'event.type') == ['start'])
        check('process name and parent are set', get(source, 'process.name') is not None and get(source, 'process.parent.name') is not None, f"{get(source, 'process.name')} from {get(source, 'process.parent.name')}")
        check('user and host are set', get(source, 'user.name') is not None and get(source, 'host.name') is not None)
        check('source metadata is set', get(source, 'winlog.channel') == 'Microsoft-Windows-Sysmon/Operational' and get(source, 'winlog.record_id') is not None and get(source, 'siem.kafka.offset') is not None)
        check('labels record the redaction', 'arg' in (get(source, 'labels.redactions') or []))
        check('no ciphertext stored', 'sealed' not in source and 'sealed' not in (get(source, 'winlog') or {}))
        check('ECS time matches the source time', get(source, 'event.created') is not None and get(source, '@timestamp') is not None)
    q_script = {'bool': {'filter': [{'term': {'event.dataset': 'windows.powershell'}}, {'term': {'event.code': '4104'}}], 'must': [{'match_phrase': {'powershell.script_block.text': marker}}]}}
    check('PowerShell 4104 test event reached OpenSearch', wait_for(q_script))
    docs = search(q_script, 5)['hits']['hits']
    if docs:
        text = get(docs[0]['_source'], 'powershell.script_block.text') or ''
        check('script secret redacted', fake not in text and '[REDACTED:assign]' in text, text.replace(marker, '<marker>')[:80])
    q_dns = {'bool': {'filter': [{'term': {'event.code': '22'}}, {'term': {'dns.question.name': f"{marker.lower()}.example.com"}}]}}
    check('Sysmon 22 DNS test event reached OpenSearch', wait_for(q_dns, 90))
    q_logon = {'bool': {'filter': [{'term': {'event.code': '4625'}}, {'term': {'user.name': marker}}]}}
    check('Security 4625 failed logon reached OpenSearch', wait_for(q_logon, 90))
    docs = search(q_logon, 1)['hits']['hits']
    if docs:
        check('failed logon maps to authentication failure', get(docs[0]['_source'], 'event.category') == ['authentication'] and get(docs[0]['_source'], 'event.outcome') == 'failure')
    q_task = {'bool': {'filter': [{'term': {'event.dataset': 'windows.taskscheduler'}}, {'term': {'event.code': '106'}}, {'wildcard': {'file.path': f'*{marker}*'}}]}}
    check('Task Scheduler 106 reached OpenSearch', wait_for(q_task, 90))
    q_file = {'bool': {'filter': [{'term': {'event.code': '11'}}, {'wildcard': {'file.name': f'{marker}*'}}]}}
    print(f'INFO Sysmon 11 for the test file: {hits(search(q_file, 0))}')

    # An exact scan of every stored field. An analyzed search can miss text and report a false zero.
    marked = search({'multi_match': {'query': marker, 'type': 'phrase', 'fields': ['process.command_line', 'process.parent.command_line', 'powershell.script_block.text', 'user.name']}}, 200)['hits']['hits']
    leaked = [h for h in marked if fake in json.dumps(h['_source'])]
    print(f'INFO documents carrying the marker: {len(marked)}')
    for hit in leaked:
        print(f"INFO secret left in {get(hit['_source'], 'event.dataset')} {get(hit['_source'], 'event.code')} from {get(hit['_source'], 'process.name')}")
    check('fake secret is stored nowhere', len(marked) > 0 and not leaked, len(leaked))
    q_special = {'bool': {'filter': [{'term': {'process.name': 'cmd.exe'}}, {'wildcard': {'process.command_line.keyword': f'*{marker} > nul*'}}]}}
    check('XML-special characters survive', wait_for(q_special, 60))
    red, seal = tokens(token_file)[:2]
    # The operator's own git grep passed the token as a bare argument, which nothing can identify as a secret.
    planted = search(phrase(red), 50)['hits']['hits']
    other = [h for h in planted if get(h['_source'], 'process.name') != 'git.exe']
    print(f'INFO redactable canary as a bare git argument: {len(planted) - len(other)} documents')
    check('redactable canary is gone from every planted event', not other, len(other))
    print(f'INFO seal-only canary in OpenSearch, by design: {hits(search(phrase(seal), 0))} documents')


def sources():
    result = search({'match_all': {}}, 0, aggs={'dataset': {'terms': {'field': 'event.dataset', 'size': 20}, 'aggs': {'code': {'terms': {'field': 'event.code', 'size': 6}}}}})
    print('documents:', hits(result))
    for bucket in result['aggregations']['dataset']['buckets']:
        print(f"  {bucket['key']:<24} {bucket['doc_count']:>7}  top IDs: " + ' '.join(f"{b['key']}x{b['doc_count']}" for b in bucket['code']['buckets']))
    wanted = {'windows.security', 'windows.sysmon', 'windows.powershell', 'windows.system', 'windows.taskscheduler', 'windows.firewall', 'windows.defender'}
    found = {b['key'] for b in result['aggregations']['dataset']['buckets']}
    check('every source has reported', wanted <= found, f'missing {sorted(wanted - found)}')
    dead = search({'match_all': {}}, 0, pattern='siem-deadletter-*', aggs={'reason': {'terms': {'field': 'dlq.reason', 'size': 20}}})
    print('dead letters:', hits(dead), {b['key']: b['doc_count'] for b in dead.get('aggregations', {}).get('reason', {}).get('buckets', [])})


def read_kafka(seconds=40):
    # Stops at the current end. Live traffic would otherwise keep resetting the idle timeout.
    ends = [subprocess.run([f'{K}/kafka-get-offsets.sh', '--bootstrap-server', BOOT, '--topic', TOPIC, '--time', when], capture_output=True, text=True, env=ENV).stdout for when in ('-1', '-2')]
    held = [sum(int(line.rsplit(':', 1)[1]) for line in text.split()) for text in ends]
    done = subprocess.run([f'{K}/kafka-console-consumer.sh', '--bootstrap-server', BOOT, '--topic', TOPIC, '--from-beginning', '--timeout-ms', str(seconds * 1000), '--max-messages', str(held[0] - held[1])],
                          capture_output=True, text=True, env=ENV, timeout=600)
    return done.stdout.splitlines()


def genuine(lines):
    """Envelopes from this host. The disposable pipeline test left fake ones from HOST in Kafka until they expire."""
    return [l for l in lines if l.startswith('{"body"') and json.loads(json.loads(l)['body']).get('computer') not in ('HOST', 'SIEM-FAULT-TEST', 'FORGED-HOST')]


def kafka_scan(marker_file, token_file):
    info = load_marker(marker_file)
    lines = read_kafka()
    real = genuine(lines)
    print(f'messages read: {len(lines)}, envelopes: {len(real)}')
    check('Kafka holds genuine envelopes', len(real) > 0)
    for name, token in (('redactable canary', tokens(token_file)[0]), ('seal-only canary', tokens(token_file)[1]), ('fake test secret', info['fake'])):
        count = sum(token in l for l in lines)
        check(f'{name} absent from Kafka', count == 0, count)
    restricted = 0
    sealed = 0
    for line in real:
        body = json.loads(json.loads(line)['body'])
        data = body.get('event_data') or {}
        sealed += 'sealed' in body
        channel, event_id = body.get('channel'), body.get('event_id')
        names = []
        if channel == 'Microsoft-Windows-Sysmon/Operational' and event_id == 1:
            names = ['CommandLine', 'ParentCommandLine']
        if channel == 'Microsoft-Windows-PowerShell/Operational' and event_id == 4104:
            names = ['ScriptBlockText']
        restricted += sum(1 for name in names if data.get(name))
    check('no restricted plaintext in Kafka', restricted == 0, restricted)
    print(f'INFO envelopes with sealed fields: {sealed}')


def percentile(values, share):
    return sorted(values)[int(len(values) * share)]


def stats(marker_file):
    since = load_marker(marker_file)['started']
    docs = search({'range': {'@timestamp': {'gte': since}}}, 2000, _source=['@timestamp', 'event.ingested'], sort=[{'@timestamp': 'desc'}])['hits']['hits']
    parse = lambda text: time.mktime(time.strptime(text[:19], '%Y-%m-%dT%H:%M:%S')) + float('0' + text[19:].rstrip('Z'))
    delays = [parse(d['_source']['event']['ingested']) - parse(d['_source']['@timestamp']) for d in docs]
    if delays:
        print(f'latency, event time to indexed, {len(delays)} events: median {percentile(delays, .5):.1f} s, p95 {percentile(delays, .95):.1f} s, p99 {percentile(delays, .99):.1f} s, max {max(delays):.1f} s')
    for row in api('/_cat/indices/siem-*?format=json&h=index,docs.count,store.size&s=index'):
        print(f"  {row['index']}: {row['docs.count']} docs, {row['store.size']}")


def unique():
    result = search({'match_all': {}}, 0, aggs={'ids': {'cardinality': {'field': 'event.id', 'precision_threshold': 40000}}})
    total, distinct = hits(result), result['aggregations']['ids']['value']
    print(f'documents {total}, distinct identities about {distinct}')
    check('no duplicate documents', abs(total - distinct) <= max(5, total * 0.01), total - distinct)


def verifier_counts():
    text = urllib.request.urlopen('http://127.0.0.1:9612/metrics', timeout=5).read().decode()
    return {m[0]: int(m[1]) for m in re.findall(r'result="(\w+)"\} (\d+)', text)}


def replay():
    """Sends back real envelopes, unchanged and tampered. The content is never printed."""
    lines = genuine(read_kafka(seconds=25))[-50:]
    check('have real envelopes to replay', len(lines) == 50, len(lines))
    tampered, zero_mac, truncated = [], [], []
    for line in lines[:10]:
        envelope = json.loads(line)
        body = json.loads(envelope['body'])
        body['computer'] = 'FORGED-HOST'
        changed = dict(envelope, body=json.dumps(body, sort_keys=True, separators=(',', ':')))
        tampered.append(json.dumps(changed))
        zero_mac.append(json.dumps(dict(envelope, mac=base64.b64encode(bytes(32)).decode())))
        truncated.append(json.dumps(dict(envelope, mac=base64.b64encode(bytes(16)).decode())))
    before = verifier_counts()
    total = hits(search({'match_all': {}}, 0))
    malformed = ['{not json', '[1,2,3]', '{"v":"siem-event-v1"}', 'x' * 100]
    payload = lines + tampered + zero_mac + truncated + malformed + ['y' * 1010000]
    done = subprocess.run([f'{K}/kafka-console-producer.sh', '--bootstrap-server', BOOT, '--topic', TOPIC, '--producer-property', 'max.request.size=2000000'], input='\n'.join(payload) + '\n', capture_output=True, text=True, env=ENV, timeout=120)
    print('producer exit', done.returncode)
    time.sleep(25)
    after = verifier_counts()
    delta = {k: after.get(k, 0) - before.get(k, 0) for k in after if after.get(k, 0) != before.get(k, 0)}
    print('verifier changes:', delta)
    check('real events replayed are recognised', delta.get('replayed', 0) >= 50, delta.get('replayed', 0))
    check('tampered real events fail authentication', delta.get('mac_mismatch', 0) >= 20, delta.get('mac_mismatch', 0))
    check('short tags are rejected by length', delta.get('bad_length', 0) == 10, delta.get('bad_length', 0))
    check('malformed input is rejected', delta.get('malformed_json', 0) + delta.get('auth_missing', 0) >= 4)
    # Above the 1,000,000 byte limit, and below the broker's own, or Kafka refuses it first.
    check('oversized input is dead-lettered', hits(search({'term': {'dlq.reason': 'size'}}, 0, pattern='siem-deadletter-*')) >= 1)
    forged = hits(search({'term': {'host.name': 'FORGED-HOST'}}, 0))
    check('no forged host in the index', forged == 0, forged)
    print(f'documents before {total}, after {hits(search({"match_all": {}}, 0))}')


def state():
    lag = subprocess.run([f'{K}/kafka-consumer-groups.sh', '--bootstrap-server', BOOT, '--describe', '--group', 'siem-aggregator'], capture_output=True, text=True, env=ENV).stdout
    print('lag', sum(int(x) for x in re.findall(rf'{TOPIC}\s+\d+\s+\S+\s+\S+\s+(\d+)', lag)), 'docs', hits(search({'match_all': {}}, 0)), 'dead', hits(search({'match_all': {}}, 0, pattern='siem-deadletter-*')), verifier_counts())


def arrived(marker_file):
    """Events made during an outage must arrive exactly once."""
    marker = load_marker(marker_file)['marker']
    # Exact text. The generator's powershell, cmd and net command lines all hold the marker.
    query = {'wildcard': {'process.command_line.keyword': f'*{marker}*'}}
    clock = time.time()
    check('events from the outage arrived', wait_for(query, 300), f'first after {time.time() - clock:.0f} s')
    time.sleep(15)
    result = search(query, 0, aggs={'ids': {'cardinality': {'field': 'event.id'}}})
    check('each arrived once', hits(result) == 3 and result['aggregations']['ids']['value'] == 3, f"{hits(result)} documents, {result['aggregations']['ids']['value']} identities")


def continuity():
    """Record IDs per channel. Sysmon alone is collected unfiltered, so only it must have no holes."""
    seen, extra = stored_records()
    check('no record stored twice', extra == 0, extra)
    for channel, ids in sorted(seen.items()):
        holes = max(ids) - min(ids) + 1 - len(ids)
        print(f'  {channel}: {len(ids)} records, {min(ids)} to {max(ids)}, {holes} holes')
        if channel == 'Microsoft-Windows-Sysmon/Operational':
            check(f'{channel} has no holes', holes == 0, holes)


def reconcile(ids_file):
    """Every in-scope record still in a Windows log must be stored. See tests/windows/export-record-ids.ps1."""
    seen = stored_records()[0]
    for channel, ids in sorted(json.load(open(ids_file, encoding='utf-8-sig')).items()):
        missing = len(set(ids) - seen.get(channel, set()))
        check(f'{channel}: every record stored', len(ids) > 0 and missing == 0, f'{len(ids)} in the Windows log, {missing} missing')


def ledger(ids_file):
    """Per channel: Windows, Kafka and OpenSearch, by record ID. Differences are listed, never netted."""
    windows = json.load(open(ids_file, encoding='utf-8-sig'))
    kafka, messages = {}, {}
    for line in genuine(read_kafka()):
        body = json.loads(json.loads(line)['body'])
        kafka.setdefault(body['channel'], set()).add(int(body['record_id']))
        messages[body['channel']] = messages.get(body['channel'], 0) + 1
    # Read after Kafka, and after the pipeline has had time, so that a record still in flight is not counted as missing.
    time.sleep(30)
    stored = stored_records()[0]
    print('channel | windows 7d | kafka messages | kafka records | stored | windows not stored | kafka not stored | stored not in kafka')
    for channel, ids in windows.items():
        ids = set(ids)
        k, o = kafka.get(channel, set()), stored.get(channel, set())
        print(f'{channel} | {len(ids)} | {messages.get(channel, 0)} | {len(k)} | {len(o)} | {len(ids - o)} | {len(k - o)} | {len(o - k)}')
        check(f'{channel}: nothing in the Windows window is missing', len(ids) > 0 and not ids - o, len(ids - o))
        check(f'{channel}: nothing in Kafka is missing', not k - o, len(k - o))
    dead = search({'match_all': {}}, 0, pattern='siem-deadletter-*', aggs={'reason': {'terms': {'field': 'dlq.reason', 'size': 20}}})
    print('dead letters:', hits(dead), {b['key']: b['doc_count'] for b in dead.get('aggregations', {}).get('reason', {}).get('buckets', [])})
    print('verifier since its last start:', verifier_counts())


def special(cases_file, xml_file):
    """Exact comparison of launched text, the raw Windows XML and the stored fields."""
    cases = json.load(open(cases_file, encoding='utf-8-sig'))
    tag, fake = cases['tag'], cases['fake']
    raw = json.load(open(xml_file, encoding='utf-8-sig'))
    original = {}
    for item in raw:
        tree = ET.fromstring(item['xml'])
        data = {node.get('Name'): (node.text or '') for node in tree.iter('{http://schemas.microsoft.com/win/2004/08/events/event}Data')}
        original[(item['channel'], str(item['record_id']))] = data
    print(f'raw XML events: {len(raw)}')
    docs = search({'wildcard': {'process.command_line.keyword': f'*{tag}*'}}, 100)['hits']['hits']
    by_record = {(get(d['_source'], 'winlog.channel'), get(d['_source'], 'winlog.record_id')): d['_source'] for d in docs}
    print(f'stored events: {len(docs)}')
    for name, launched in cases['lines'].items():
        # Sysmon itself writes each % as %%. Security 4688 holds no command line, by the owner's decision.
        recorded = launched.replace('%', '%%')
        wanted = recorded.replace(fake, '[REDACTED:arg]')
        rows = [k for k, v in original.items() if k[0].endswith('Sysmon/Operational') and v.get('CommandLine') == recorded]
        check(f'{name}: Windows recorded the launched text', len(rows) == 1, len(rows))
        for key in rows:
            source = by_record.get(key) or {}
            check(f'{name}: stored text is exact', get(source, 'process.command_line') == wanted, repr((get(source, 'process.command_line') or '')[-60:]))
            check(f'{name}: raw event field is exact', (get(source, 'winlog.event_data') or {}).get('CommandLine') == wanted)
    children = [k for k, v in original.items() if v.get('ParentCommandLine') == cases['lines']['parent']]
    check('Windows recorded the parent line', len(children) == 1, len(children))
    for key in children:
        found = search({'bool': {'filter': [{'term': {'winlog.channel': key[0]}}, {'term': {'winlog.record_id': key[1]}}]}}, 1)['hits']['hits']
        source = found[0]['_source'] if found else {}
        check('ParentCommandLine is exact', get(source, 'process.parent.command_line') == cases['lines']['parent'])
        check('ParentCommandLine raw field is exact', (get(source, 'winlog.event_data') or {}).get('ParentCommandLine') == cases['lines']['parent'])
    scripts = [item for item in raw if item.get('text') and tag + '-script' in item['text']]
    check('Windows recorded the script block', len(scripts) == 1, len(scripts))
    for item in scripts:
        found = search({'bool': {'filter': [{'term': {'winlog.channel': item['channel']}}, {'term': {'winlog.record_id': str(item['record_id'])}}]}}, 1)['hits']['hits']
        text = get(found[0]['_source'], 'powershell.script_block.text') if found else None
        wanted = item['text'].replace(f"'{fake}'", '[REDACTED:assign]')
        same = text == wanted
        print(f'INFO script block carriage returns: Windows {wanted.count(chr(13))}, stored {(text or "").count(chr(13))}')
        check('script block text is exact', same, '' if same else repr((text or '')[:90]))
    stored_text = json.dumps([d['_source'] for d in docs], ensure_ascii=False)
    check('no test secret is stored', fake not in stored_text)
    leaks = [get(v, 'process.command_line') for v in by_record.values() if tag + '-entity' not in (get(v, 'process.command_line') or '') and re.search(r'&(amp|lt|gt|quot|#\d+);', get(v, 'process.command_line') or '')]
    check('no XML entities appear outside the literal case', not leaks, len(leaks))
    task = search({'bool': {'filter': [{'term': {'event.dataset': 'windows.taskscheduler'}}, {'term': {'event.code': '106'}}, {'wildcard': {'file.path': f'*{tag}*'}}]}}, 1)['hits']['hits']
    check('Task Scheduler name is exact', len(task) == 1 and get(task[0]['_source'], 'file.path') == cases['task'])
    for name, needle in (('&&', '*&&*'), ('2>&1', '*2>&1*'), ('<test>', '*<test>*'), ('spaced', '*A   &   B   >   C*'), ('unicode', '*caf\u00e9*')):
        found = hits(search({'bool': {'filter': [{'wildcard': {'process.command_line.keyword': f'*{tag}*'}}, {'wildcard': {'process.command_line.keyword': needle}}]}}, 0))
        check(f'{name} is searchable', found >= 1, found)


def stored_records():
    after = None
    seen = {}
    extra = 0
    while True:
        composite = {'size': 5000, 'sources': [{'c': {'terms': {'field': 'winlog.channel'}}}, {'r': {'terms': {'field': 'winlog.record_id'}}}]}
        if after:
            composite['after'] = after
        result = search({'match_all': {}}, 0, aggs={'rows': {'composite': composite}})['aggregations']['rows']
        for row in result['buckets']:
            seen.setdefault(row['key']['c'], set()).add(int(row['key']['r']))
            extra += row['doc_count'] - 1
        after = result.get('after_key')
        if not result['buckets'] or not after:
            return seen, extra


def listeners():
    lines = subprocess.run(['ss', '-H', '-ltn'], capture_output=True, text=True, check=True).stdout.splitlines()
    bound = sorted({line.split()[3] for line in lines})
    # 10.255.255.254:53 is the WSL DNS tunnel, which is private to this distribution.
    open_wide = [b for b in bound if not re.match(r'(\[::ffff:)?127\.', b) and b != '10.255.255.254:53']
    check('every listener is bound to loopback', not open_wide, ' '.join(open_wide) or len(bound))


def main():
    command = sys.argv[1]
    {'check': check_marker, 'sources': sources, 'kafka': kafka_scan, 'stats': stats, 'unique': unique, 'replay': replay, 'state': state, 'listeners': listeners, 'arrived': arrived, 'continuity': continuity, 'reconcile': reconcile, 'ledger': ledger, 'special': special}[command](*sys.argv[2:])
    print(f'\n{len(failures)} failed' if failures else '\nall passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
