"""Measures the correlation path alone, with no network: alerts per second, per-alert time and memory.

The evidence calls are stubbed, so real rates are limited by OpenSearch round trips, which the live run shows.
"""
import random
import resource
import sys
import tempfile
import time
import unittest

import helpers
from helpers import GROUP, LOLBIN, MIN, NOW, RUNKEY, SCHTASKS, SCRIPT, TASK, World, alert


class Case(unittest.TestCase):
    def runTest(self):
        pass


def main(count):
    case = Case()
    world = World(case)
    random.seed(11)
    rules = (GROUP, SCHTASKS, RUNKEY, SCRIPT, TASK, LOLBIN)
    docs = [alert(random.choice(rules), NOW + i * 2000, user=f'user{i % 40}', host=f'host{i % 8}', tactics=(random.choice(('execution', 'persistence', 'discovery', 'stealth')),)) for i in range(count)]
    start = time.perf_counter()
    times = []
    for offset in range(0, count, 200):
        world.kafka.send(*docs[offset:offset + 200])
        world.service.poll_kafka()
        batch = time.perf_counter()
        world.service.process(200)
        times.append((time.perf_counter() - batch) / max(len(docs[offset:offset + 200]), 1))
    spent = time.perf_counter() - start
    times.sort()
    print(f'{count} alerts in {spent:.1f} s: {count / spent:.0f} per second')
    print(f'per alert, by batch: median {times[len(times) // 2] * 1000:.1f} ms, worst {times[-1] * 1000:.1f} ms')
    print(f"incidents {len(world.store.list_incidents(None, 100000))}, outbox {world.store.outbox_size()}, held {world.store.counts()}")
    print(f'peak memory {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024} MiB')
    case.doCleanups()


if __name__ == '__main__':
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000)
