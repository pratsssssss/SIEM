"""Small read-only questions about the running detector, as root in WSL. Prints yes, no or a count."""
import json
import sqlite3
import subprocess
import sys

API = 'https://127.0.0.1:9200'
STATE = '/home/linux/siem/data/detector/state.db'
K = '/opt/kafka/bin'
ENV = {'JAVA_HOME': '/usr/lib/jvm/java-17-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'KAFKA_HEAP_OPTS': '-Xmx128m', 'KAFKA_JMX_OPTS': ' '}


def search(pattern, body):
    done = subprocess.run(['curl', '-sS', '--max-time', '20', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', '-H', 'Content-Type: application/json', '-d', json.dumps(body), f'{API}/{pattern}/_search'], capture_output=True, text=True)
    return json.loads(done.stdout)


def event_id(task):
    query = {'bool': {'filter': [{'term': {'event.code': '106'}}, {'wildcard': {'file.path': f'*{task}*'}}]}}
    hits = search('siem-windows-*', {'size': 1, 'query': query}).get('hits', {}).get('hits', [])
    return hits[0]['_id'] if hits else None


def db():
    return sqlite3.connect(f'file:{STATE}?mode=ro', uri=True, timeout=10)


def kafka_rows():
    ends = subprocess.run([f'{K}/kafka-get-offsets.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--time', '-1'], capture_output=True, text=True, env=ENV).stdout
    total = sum(int(line.rsplit(':', 1)[1]) for line in ends.split())
    done = subprocess.run([f'{K}/kafka-console-consumer.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--from-beginning', '--max-messages', str(total), '--timeout-ms', '15000', '--property', 'print.key=true', '--property', 'key.separator=\t'], capture_output=True, text=True, env=ENV, timeout=90)
    return [line.partition('\t') for line in done.stdout.splitlines()]


def main():
    command = sys.argv[1]
    if command == 'state':
        with db() as c:
            pending = c.execute('SELECT COUNT(*) FROM alerts WHERE index_done = 0 OR kafka_done = 0').fetchone()[0]
            stored = c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
            failing = c.execute('SELECT COUNT(*) FROM rule_state WHERE failures > 0').fetchone()[0]
        print(f'alerts held {stored}, pending {pending}, rules failing {failing}')
    elif command == 'event':
        print('yes' if event_id(sys.argv[2]) else 'no')
    elif command == 'evidence-waiting':
        doc = event_id(sys.argv[2])
        with db() as c:
            rows = c.execute('SELECT COUNT(*) FROM alerts WHERE kafka_done = 0').fetchone()[0]
        print('yes' if doc and rows else 'no')
    elif command == 'in-kafka':
        doc = event_id(sys.argv[2])
        print('yes' if doc and any(doc in value for _, _, value in kafka_rows()) else 'no')
    elif command == 'rule-failures':
        with db() as c:
            print('yes' if c.execute('SELECT COUNT(*) FROM rule_state WHERE failures > 0').fetchone()[0] else 'no')
    elif command == 'duplicates':
        keys = [key for key, _, _ in kafka_rows() if len(key) == 32]
        print(f'{len(keys)} messages, {len(set(keys))} distinct alert IDs')


if __name__ == '__main__':
    main()
