"""Live enrichment checks, as root in WSL. Reads with the admin account, and changes only the synthetic file.

Usage: run_live_enrichment.py prepare <marker.json> | verify <marker.json> | independence <marker.json> | clean
"""
import json
import subprocess
import sys
import time
from pathlib import Path

API = 'https://127.0.0.1:9200'
OWNER = Path('/home/linux/siem/data/enrichment/owner')
SYNTHETIC = OWNER / 'synthetic-test.csv'
K = '/opt/kafka/bin'
ENV = {'JAVA_HOME': '/usr/lib/jvm/java-17-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'KAFKA_HEAP_OPTS': '-Xmx128m', 'KAFKA_JMX_OPTS': ' '}
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def api(path, body=None, method=None):
    command = ['curl', '-sS', '--max-time', '30', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', f'{API}{path}']
    if method:
        command += ['-X', method]
    if body is not None:
        command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    return json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)


def search(pattern, query, size=50, **extra):
    api(f'/{pattern}/_refresh', method='POST')
    return api(f'/{pattern}/_search', {'size': size, 'track_total_hits': True, 'query': query, **extra})


def hits(result):
    return result['hits']['hits']


def run(*args):
    return subprocess.run(['runuser', '-u', 'siem-enricher', '--', '/usr/local/bin/siem-enricher', *args], capture_output=True, text=True).stdout


def wait(test, seconds, name):
    clock = time.time()
    while time.time() - clock < seconds:
        found = test()
        if found:
            return found
        time.sleep(10)
    check(name, False, f'not within {seconds} s')
    return None


def enriched(indicator, doc_type=None):
    query = {'bool': {'filter': [{'term': {'indicators.value': indicator}}, *([{'term': {'doc_type': doc_type}}] if doc_type else [])]}}
    return hits(search('siem-enrichment-*', query, sort=[{'enriched_at': 'desc'}]))


def indicator(document, value):
    return next(i for i in document['indicators'] if i['value'] == value)


def prepare(marker):
    info = json.load(open(marker, encoding='utf-8-sig'))
    OWNER.mkdir(exist_ok=True)
    SYNTHETIC.write_text(''.join([
        '# Synthetic test intelligence. Nothing here is really malicious.\n',
        f"ip,{info['ip']},synthetic-c2\n", f"domain,{info['domain']},synthetic-c2\n",
        f"sha256,{info['sha256']},synthetic-family\n", f"url,{info['url']},synthetic-phishing\n",
    ]))
    subprocess.run(['chown', 'siem-enricher:siem-enricher', str(SYNTHETIC)], check=True)
    print(run('feeds', 'update', '--name', 'owner-synthetic-test').strip())
    subprocess.run(['systemctl', 'restart', 'siem-enricher'], check=True)
    print('enricher restarted with the synthetic file')


def verify(marker):
    info = json.load(open(marker, encoding='utf-8-sig'))
    ip, domain, sha256, url, secret = info['ip'], info['domain'], info['sha256'], info['url'], info['secret']

    docs = wait(lambda: enriched(domain, 'event'), 300, 'domain found in telemetry')
    if docs:
        found = docs[0]['_source']
        check('use case 2: known malicious domain in DNS telemetry', indicator(found, domain)['verdict'] == 'malicious', indicator(found, domain)['sources'][0]['source'])
        check('the event is linked by its own ID', found['event_id'] == docs[0]['_source']['threat']['enrichments'][0]['matched']['id'])
        event = api(f"/{found['event_index']}/_doc/{found['event_id']}")
        check('the original event is untouched', event.get('_version') == 1 and 'threat' not in event['_source'], f"version {event.get('_version')}")

    docs = wait(lambda: enriched(ip, 'event'), 300, 'IP found in telemetry')
    if docs:
        found = indicator(docs[0]['_source'], ip)
        check('use case 1: malicious external IP in network telemetry', found['verdict'] == 'malicious')
        check('geography and ASN are attached', bool(found['context'].get('country') and found['context'].get('asn')), found['context'])

    docs = wait(lambda: enriched(sha256), 300, 'hash found in telemetry')
    if docs:
        check('use case 3: file hash of known malware', indicator(docs[0]['_source'], sha256)['verdict'] == 'malicious', f"{len(docs)} documents")
        check('the malware name is carried', 'synthetic-family' in json.dumps(indicator(docs[0]['_source'], sha256)['sources']))

    docs = wait(lambda: enriched(url, 'alert'), 420, 'URL found in alert evidence')
    if docs:
        document = docs[0]['_source']
        found = indicator(document, url)
        check('use case 4: suspicious URL in alert evidence', found['verdict'] == 'malicious')
        check('the URL came from restricted text, so it was not eligible for external lookup', found['from_restricted_text'] and not found['external_checked'])
        check('the alert ID links to the alert', document['alert_ref'].endswith(document['alert_id']))
        alert = api(f"/{document['alert_ref'].rsplit('/', 1)[0]}/_doc/{document['alert_id']}")
        check('the alert itself is unchanged', alert.get('_version') == 1 and 'enrichment' not in alert['_source'], f"version {alert.get('_version')}")
        check('alert severity is untouched', alert['_source']['severity'] == document['alert_severity'], alert['_source']['severity'])
        check('source references are preserved', document['raw_event_refs'] == alert['_source']['raw_event_refs'], len(document['raw_event_refs']))
        check('the secret is not in the enrichment document', secret not in json.dumps(document))
        check('status is visible', document['status'] in ('complete', 'partial'), document['status'])

    text = json.dumps([d['_source'] for d in hits(search('siem-enrichment-*', {'match_all': {}}, 1000))])
    check('the test secret is nowhere in the enrichment index', secret not in text)
    private = [i for d in hits(search('siem-enrichment-*', {'term': {'doc_type': 'alert'}}, 1000)) for i in d['_source']['indicators'] if i['type'] == 'ip' and i['value'].startswith(('10.', '127.', '192.168.', '169.254.'))]
    check('use case 10: no private address was checked externally', not any(i['external_checked'] for i in private), f'{len(private)} private addresses seen')
    check('private addresses are not called clean', not any(i['verdict'] == 'no_known_threat' for i in private))


def kafka_rows():
    ends = subprocess.run([f'{K}/kafka-get-offsets.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--time', '-1'], capture_output=True, text=True, env=ENV).stdout
    total = sum(int(line.rsplit(':', 1)[1]) for line in ends.split())
    done = subprocess.run([f'{K}/kafka-console-consumer.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--from-beginning', '--max-messages', str(total), '--timeout-ms', '15000', '--property', 'print.key=true', '--property', 'key.separator=\t'], capture_output=True, text=True, env=ENV, timeout=90)
    return [line.partition('\t') for line in done.stdout.splitlines() if len(line.partition('\t')[0]) == 32]


def independence(marker):
    info = json.load(open(marker, encoding='utf-8-sig'))
    rows = kafka_rows()
    text = '\n'.join(value for _, _, value in rows)
    print(f'INFO alert messages {len(rows)}')
    check('alert IDs stay unique on Kafka', len({k for k, _, _ in rows}) == len(rows))
    check('the test secret is not on Kafka', info['secret'] not in text)
    check('no restricted field is plain text on Kafka', not any(name in text for name in ('"process.command_line": ["', '"process.parent.command_line": ["', '"file.path": ["')))
    check('no enrichment data was added to the alert topic', '"enrichment"' not in text and 'verdict' not in text)
    topics = subprocess.run([f'{K}/kafka-topics.sh', '--bootstrap-server', '127.0.0.1:9092', '--list'], capture_output=True, text=True, env=ENV).stdout.split()
    check('no new Kafka topic exists', not any('enrich' in t for t in topics), ' '.join(topics))


def clean():
    if SYNTHETIC.exists():
        print(run('feeds', 'purge', '--name', 'owner-synthetic-test').strip())
        SYNTHETIC.unlink()
    subprocess.run(['systemctl', 'restart', 'siem-enricher'], check=True)
    print('synthetic intelligence removed')


if __name__ == '__main__':
    action = sys.argv[1]
    {'prepare': prepare, 'verify': verify, 'independence': independence}.get(action, lambda _: clean())(sys.argv[2] if len(sys.argv) > 2 else None)
    print(f'{len(failures)} failed' if failures else 'all passed')
    sys.exit(1 if failures else 0)
