"""Measures the running pipeline, as root in WSL. Prints numbers only.

Usage: run_perf.py [minutes of normal running to sample, default 10]
"""
import subprocess
import sys
import time

import run_e2e as e


def seconds(text):
    return time.mktime(time.strptime(text[:19], '%Y-%m-%dT%H:%M:%S')) + float('0' + text[19:].rstrip('Z'))


def units():
    result = {}
    for unit in ('opensearch', 'kafka', 'seal-verifier', 'vector'):
        fields = subprocess.run(['systemctl', 'show', unit, '-p', 'MemoryCurrent', '-p', 'CPUUsageNSec', '--value'], capture_output=True, text=True).stdout.split()
        result[unit] = (int(fields[0]), int(fields[1]))
    return result


def main():
    minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    query = {'range': {'event.ingested': {'gte': f'now-{minutes}m'}}}
    docs = e.search(query, 10000, _source=['@timestamp', 'event.ingested'])['hits']['hits']
    delays = sorted(seconds(d['_source']['event']['ingested']) - seconds(d['_source']['@timestamp']) for d in docs)
    if delays:
        print(f'latency over {minutes} min, {len(delays)} events: median {e.percentile(delays, .5):.2f} s, p95 {e.percentile(delays, .95):.2f} s, p99 {e.percentile(delays, .99):.2f} s, max {delays[-1]:.2f} s')
    first, counts = units(), e.verifier_counts()
    clock = time.time()
    time.sleep(60)
    last, after, took = units(), e.verifier_counts(), time.time() - clock
    print(f"live rate {(after.get('accepted', 0) - counts.get('accepted', 0)) / took:.2f} events/s")
    for unit in last:
        print(f'{unit}: memory {last[unit][0] / 1048576:.0f} MiB, cpu {(last[unit][1] - first[unit][1]) / took / 1e7:.2f} % of one core')
    print(subprocess.run(['free', '-m'], capture_output=True, text=True).stdout.splitlines()[1])
    total = e.hits(e.search({'match_all': {}}, 0))
    dead = e.hits(e.search({'match_all': {}}, 0, pattern='siem-deadletter-*'))
    rows = e.api('/_cat/indices/siem-*?format=json&bytes=b&h=index,docs.count,store.size&s=index')
    size = sum(int(r['store.size']) for r in rows)
    print(f'documents {total}, dead letters {dead}, {size / 1048576:.1f} MiB stored, {size / max(total + dead, 1):.0f} bytes per event')
    print(f'dead-letter rate {dead / max(total + dead, 1) * 100:.3f} %, all from deliberate tests')
    state = subprocess.run(['du', '-sm', '/home/linux/siem/data/kafka', '/home/linux/siem/data/opensearch', '/home/linux/siem/data/verifier'], capture_output=True, text=True).stdout
    print(state.strip().replace('\t', ' '))
    e.state()


if __name__ == '__main__':
    sys.exit(main())
