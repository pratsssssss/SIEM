"""Timing tests for D22 MAC verification. Random data only, no keys or events from the system.

Measures with Welch's t-test, as dudect does: 4.5 or more means the groups differ.

Only the 1 MiB cases are gates. On this host the null controls, whose groups are identical, have
reached |t| 16 at 32 bytes, so 32-byte results are noise-limited and are reported as INFO. No
result here can prove code is constant-time. Each VRL case times only the operation under test.

Usage: python tests/vector/run_timing.py <path to vector executable> [rounds]
"""
import json
import hmac
import math
import pathlib
import random
import secrets
import statistics
import subprocess
import sys
import tempfile
import time

THRESHOLD = 4.5
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 40
PER_ROUND = 3000
LONG = 1 << 20


def welch(a, b):
    """Crops the slowest 10%, then returns t. Interrupts only ever make a sample slower."""
    a, b = sorted(a)[:int(len(a) * .9)], sorted(b)[:int(len(b) * .9)]
    va, vb = statistics.variance(a), statistics.variance(b)
    denominator = math.sqrt(va / len(a) + vb / len(b))
    if denominator == 0:
        return 0.0 if statistics.fmean(a) == statistics.fmean(b) else math.inf
    return (statistics.fmean(a) - statistics.fmean(b)) / denominator


def report(name, groups, expect_leak=None):
    labels = list(groups)
    worst = max((abs(welch(groups[x], groups[y])) for i, x in enumerate(labels) for y in labels[i + 1:]))
    medians = ', '.join(f'{k}={statistics.median(v):.0f} ns' for k, v in groups.items())
    leak = worst >= THRESHOLD
    ok = leak == expect_leak
    kind = {True: 'control, must differ', False: 'must not differ', None: 'informational'}[expect_leak]
    verdict = 'INFO' if expect_leak is None else 'PASS' if ok else 'FAIL'
    print(f"{verdict} {name} ({kind}): |t|={worst:.1f}, n={len(groups[labels[0]])} per group, {medians}")
    return ok


def vrl_samples(vector, work, program, values, rounds=ROUNDS, per_round=PER_ROUND):
    """Runs one shuffled batch per line, and returns nanoseconds per class."""
    config = {
        'data_dir': str(work),
        'sources': {'in': {'type': 'stdin', 'decoding': {'codec': 'json'}, 'max_length': 1 << 28}},
        'transforms': {'t': {'type': 'remap', 'inputs': ['in'], 'source': PREFIX + program + SUFFIX}},
        'sinks': {'out': {'type': 'console', 'inputs': ['t'], 'encoding': {'codec': 'json'}}},
    }
    path = work / 'timing.json'
    path.write_text(json.dumps(config), encoding='utf8')
    labels = list(values)
    lines = [json.dumps({'vals': values, 'order': [random.choice(labels) for _ in range(per_round)]})
             for _ in range(rounds)]
    done = subprocess.run([vector, '--config', str(path), '--quiet'], input='\n'.join(lines) + '\n',
                          capture_output=True, text=True, timeout=540)
    if done.returncode != 0:
        raise SystemExit(f'vector exited {done.returncode}: {done.stderr[-400:]}')
    groups = {}
    rows = [json.loads(line) for line in done.stdout.splitlines() if line.startswith('{')]
    for row in rows[1:]:  # The first round warms caches.
        for label, ns, _ in row['out']:
            groups.setdefault(label, []).append(ns)
    return groups


# Values are decoded once, outside the timed region. Only reference counts move inside it.
PREFIX = r'''
vals = {}
for_each(object!(.vals)) -> |label, v| {
  vals = set!(vals, [label], {"a": decode_base16!(string!(v.a)), "b": decode_base16!(string!(v.b))})
}
.out = map_values(array!(.order)) -> |label| {
  a = string!(get!(vals, [string!(label), "a"]))
  b = string!(get!(vals, [string!(label), "b"]))
'''
SUFFIX = r'''
  [label, t1 - t0, r]
}
del(.vals)
del(.order)
'''
START = 't0 = to_unix_timestamp!(now(), unit: "nanoseconds")'
STOP = 't1 = to_unix_timestamp!(now(), unit: "nanoseconds")'
# Plain comparison, as control.
RAW = f'''
  {START}
  r = a != b
  {STOP}
'''
# The aggregator's line 139, timing the final comparison only.
BLIND_COMPARE = f'''
  blind = random_bytes!(32)
  ha = hmac(a, blind, "SHA-256")
  hb = hmac(b, blind, "SHA-256")
  {START}
  r = ha != hb
  {STOP}
'''
# The aggregator's lines 138 and 139, timing the whole verification.
BLIND_WHOLE = f'''
  {START}
  blind = random_bytes!(32)
  r = hmac(a, blind, "SHA-256") != hmac(b, blind, "SHA-256")
  {STOP}
'''


def prefix_cases(size, positions):
    """Wrong values that match the expected value up to, and not including, each position."""
    expected = secrets.token_bytes(size)
    cases = {}
    for label, position in positions.items():
        wrong = bytearray(expected)
        wrong[position] ^= 0xff
        cases[label] = {'a': bytes(wrong).hex(), 'b': expected.hex()}
    return cases


def python_samples(compare, a, cases, n=120000):
    groups = {label: [] for label in cases}
    order = [random.choice(list(cases)) for _ in range(n)]
    clock = time.perf_counter_ns
    for label in order:
        b = cases[label]
        t0 = clock()
        compare(a, b)
        groups[label].append(clock() - t0)
    return groups


def python_cases(size):
    a = secrets.token_bytes(size)
    first, last = bytearray(a), bytearray(a)
    first[0] ^= 0xff
    last[-1] ^= 0xff
    return a, {'first': bytes(first), 'last': bytes(last)}


def main(vector):
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        print(f'{vector}, {ROUNDS} rounds of {PER_ROUND}')

        one_mib = prefix_cases(LONG, {'first': 0, 'last': LONG - 1})
        results.append(report('VRL != on 1 MiB, difference at first vs last byte',
                              vrl_samples(vector, work, RAW, one_mib, 12, 400), True))

        short = {'p0': 0, 'p8': 8, 'p16': 16, 'p31': 31}
        report('VRL != on 32 bytes', vrl_samples(vector, work, RAW, prefix_cases(32, short)))
        # Null controls: both groups are the same input, so any t here is measurement noise.
        same = prefix_cases(32, {'x': 8})
        same['y'] = same['x']
        report('Null, VRL != on 32 bytes', vrl_samples(vector, work, RAW, same))
        report('Null, double HMAC whole verification', vrl_samples(vector, work, BLIND_WHOLE, same))
        report('Double HMAC, final compare only, MAC closeness to expected',
               vrl_samples(vector, work, BLIND_COMPARE, prefix_cases(32, short)))
        report('Double HMAC, whole verification, MAC closeness to expected',
               vrl_samples(vector, work, BLIND_WHOLE, prefix_cases(32, short)))

    a, cases = python_cases(LONG)
    results.append(report('Python == on 1 MiB, first vs last byte',
                          python_samples(lambda x, y: x == y, a, cases, 6000), True))
    results.append(report('hmac.compare_digest on 1 MiB, first vs last byte',
                          python_samples(hmac.compare_digest, a, cases, 6000), False))
    a, cases = python_cases(32)
    report('Null, hmac.compare_digest on 32 bytes', python_samples(hmac.compare_digest, a, {'x': cases['first'], 'y': cases['first']}))
    report('hmac.compare_digest on 32 bytes, first vs last byte', python_samples(hmac.compare_digest, a, cases))
    print(f"\n{sum(results)} of {len(results)} gated results as expected")
    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
