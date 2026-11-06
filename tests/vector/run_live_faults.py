"""Faults on the live pipeline, as root in WSL. Signs with the real key, which it never prints.

Writes only labelled test messages to Kafka. They reach the dead letters, never the event index.
Usage: run_live_faults.py [oversized | holds]
"""
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time

import run_e2e as e

KEYS = '/home/linux/siem/config/verifier/field-keys.json'
TEST_HOST = 'SIEM-FAULT-TEST'


def sign(body):
    text = json.dumps(body, sort_keys=True, separators=(',', ':'))
    key = bytes.fromhex(json.load(open(KEYS))['k1_mac'])
    mac = hmac.new(key, f'siem-event-v1|k1|{text}'.encode(), hashlib.sha256).digest()
    return json.dumps({'body': text, 'event_uid': body['event_uid'], 'k': 'k1', 'mac': base64.b64encode(mac).decode(), 'v': 'siem-event-v1'}, sort_keys=True, separators=(',', ':'))


def produce(lines):
    done = subprocess.run([f'{e.K}/kafka-console-producer.sh', '--bootstrap-server', e.BOOT, '--topic', e.TOPIC], input='\n'.join(lines) + '\n', capture_output=True, text=True, env=e.ENV, timeout=120)
    assert done.returncode == 0, 'producer failed'


def block(index, on):
    e.api(f'/{index}/_settings', {'index': {'blocks': {'write': on}}}, 'PUT')


def dead(reason):
    return e.hits(e.search({'term': {'dlq.reason': reason}}, 0, pattern='siem-deadletter-*'))


def docs():
    return e.hits(e.search({'match_all': {}}, 0))


def lag():
    text = subprocess.run([f'{e.K}/kafka-consumer-groups.sh', '--bootstrap-server', e.BOOT, '--describe', '--group', 'siem-aggregator'], capture_output=True, text=True, env=e.ENV).stdout
    return sum(int(x) for x in e.re.findall(rf'{e.TOPIC}\s+\d+\s+\S+\s+\S+\s+(\d+)', text))


def settle(test, seconds=90):
    for _ in range(seconds // 3):
        if test():
            return True
        time.sleep(3)
    return False


def oversized():
    # Above the aggregator's 1,000,000 byte limit, and below the broker's own, or Kafka refuses it first.
    before = dead('size')
    produce(['y' * 1010000])
    e.check('oversized input is dead-lettered by digest alone', settle(lambda: dead('size') == before + 1, 60), dead('size') - before)
    stored = e.search({'term': {'dlq.reason': 'size'}}, 1, pattern='siem-deadletter-*')['hits']['hits'][0]['_source']
    e.check('the dead letter holds no content', 'raw' not in stored and len(json.dumps(stored)) < 2000, len(json.dumps(stored)))
    print(f'{len(e.failures)} failed' if e.failures else 'all passed')
    return 1 if e.failures else 0


def committed():
    text = subprocess.run([f'{e.K}/kafka-consumer-groups.sh', '--bootstrap-server', e.BOOT, '--describe', '--group', 'siem-aggregator'], capture_output=True, text=True, env=e.ENV).stdout
    return sum(int(x) for x in e.re.findall(rf'{e.TOPIC}\s+\d+\s+(\d+)\s+\d+\s+\d+', text))


def hold(unit, count_docs):
    """Offsets must not advance during an outage, so nothing is acknowledged before it is stored."""
    total = docs() if count_docs else None
    subprocess.run(['systemctl', 'stop', unit], check=True)
    time.sleep(20)
    first, waiting = committed(), lag()
    time.sleep(45)
    last, later = committed(), lag()
    e.check(f'{unit} down: committed offsets did not advance', first == last, f'{first} and {last}')
    e.check(f'{unit} down: unread events are building up in Kafka', later > waiting, f'lag {waiting} then {later}')
    if count_docs:
        e.check(f'{unit} down: nothing bypassed it into OpenSearch', docs() - total < 400 and docs() == docs(), docs() - total)
        steady = docs()
        time.sleep(15)
        e.check(f'{unit} down: the index is not growing', docs() == steady, docs() - steady)
    subprocess.run(['systemctl', 'start', unit], check=True)
    e.check(f'{unit} back: offsets advance again', settle(lambda: committed() > last, 120), committed() - last)
    e.check(f'{unit} back: Kafka drains', settle(lambda: lag() < 200, 180), f'lag {lag()}')


def holds():
    hold('seal-verifier', True)
    hold('opensearch', False)
    fallback = e.hits(e.search({'term': {'labels.xml_fallback': True}}, 0))
    e.check('no live event fell back to the damaged text', fallback == 0, fallback)
    print(f'{len(e.failures)} failed' if e.failures else 'all passed')
    return 1 if e.failures else 0


def main():
    bodies = [json.loads(json.loads(line)['body']) for line in e.genuine(e.read_kafka(seconds=25))]
    plain = [b for b in bodies if b.get('channel') == 'Security' and b.get('event_id') == 4624 and 'sealed' not in b]
    today = time.strftime('%Y.%m.%d', time.gmtime())
    older = [b for b in plain if not b['timestamp'].startswith(today.replace('.', '-'))]
    e.check('have real unsealed events to work from', len(plain) > 5 and len(older) > 1, f'{len(plain)} and {len(older)}')

    # A correctly signed event that tries to change a stored identity.
    target = plain[-1]
    hit = e.search({'term': {'event.id': e.get(target, 'event_uid')}}, 1, version=True)['hits']['hits']
    e.check('the identity under test is stored', len(hit) == 1)
    before = hit[0]['_version']
    conflicts = dead('replay_conflict')
    produce([sign(dict(target, computer=TEST_HOST))])
    e.check('changed identity is refused as replay_conflict', settle(lambda: dead('replay_conflict') == conflicts + 1), dead('replay_conflict') - conflicts)
    after = e.search({'term': {'event.id': target['event_uid']}}, 1, version=True)['hits']['hits'][0]
    e.check('the stored document did not change', after['_version'] == before and e.get(after['_source'], 'host.name') != TEST_HOST, f"version {after['_version']}")

    # A valid event OpenSearch refuses must go to the dead letters, and must not stall live events.
    source = older[-1]
    index = 'siem-windows-' + source['timestamp'][:10].replace('-', '.')
    uid = hashlib.sha256(f'{TEST_HOST}|{time.time()}'.encode()).hexdigest()
    poison = dict(source, event_uid=uid, record_id=999000001, computer=TEST_HOST)
    rejected = dead('index_rejected')
    total = docs()
    block(index, True)
    try:
        produce([sign(poison)])
        e.check('a refused document is dead-lettered', settle(lambda: dead('index_rejected') == rejected + 1, 120), dead('index_rejected') - rejected)
        e.check('live events keep flowing past it', settle(lambda: docs() > total, 60), docs() - total)
    finally:
        block(index, False)
    e.check('the refused document is not stored', e.hits(e.search({'term': {'host.name': TEST_HOST}}, 0)) == 0)

    # Dead-letter storage failure: hold, and lose nothing.
    dead_index = e.api('/_cat/indices/siem-deadletter-*?format=json&h=index&s=index')[-1]['index']
    malformed = dead('malformed_json')
    block(dead_index, True)
    try:
        produce(['{dead-letter-hold-test'])
        time.sleep(20)
        held = lag()
        e.check('dead-letter failure holds the offset', held >= 1, f'lag {held}')
        e.check('the event was not recorded as handled', dead('malformed_json') == malformed)
    finally:
        block(dead_index, False)
    e.check('dead letter is written after recovery', settle(lambda: dead('malformed_json') == malformed + 1, 120), dead('malformed_json') - malformed)
    e.check('ingestion recovers', settle(lambda: lag() < 200, 120), f'lag {lag()}')
    print(f'\n{len(e.failures)} failed' if e.failures else '\nall passed')
    return 1 if e.failures else 0


if __name__ == '__main__':
    raise SystemExit({'oversized': oversized, 'holds': holds}.get(sys.argv[1] if len(sys.argv) > 1 else '', main)())
