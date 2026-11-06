"""Evaluates the small Query DSL subset the detector emits, against plain documents.

It lets rules be tested with no OpenSearch running. tests/detection/test_live_parity.py runs the same
fixtures on real OpenSearch and fails if the two ever disagree.
"""
import ipaddress
import re


def _values(doc, name):
    if name.endswith('.keyword'):
        name = name[:-len('.keyword')]
    if name in doc:
        value = doc[name]
    else:
        value = doc
        for part in name.split('.'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                # winlog.event_data keys can contain dots or spaces.
                return []
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _wildcard_regex(pattern):
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == '\\' and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append('.*' if c == '*' else '.' if c == '?' else re.escape(c))
        i += 1
    return ''.join(out)


def _term(value, wanted):
    if isinstance(wanted, str) and '/' in wanted:
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(wanted, strict=False)
        except ValueError:
            return False
    return str(value) == str(wanted)


def _in_range(value, spec):
    checks = {'gt': lambda a, b: a > b, 'gte': lambda a, b: a >= b, 'lt': lambda a, b: a < b, 'lte': lambda a, b: a <= b}
    return all(checks[op](value, bound) for op, bound in spec.items() if op in checks)


def matches(query, doc):
    if not query:
        return True
    kind, body = next(iter(query.items()))
    if kind == 'bool':
        if not all(matches(q, doc) for q in body.get('filter', []) + body.get('must', [])):
            return False
        if any(matches(q, doc) for q in body.get('must_not', [])):
            return False
        should = body.get('should', [])
        return not should or sum(matches(q, doc) for q in should) >= body.get('minimum_should_match', 1)
    if kind == 'term':
        name, wanted = next(iter(body.items()))
        wanted = wanted['value'] if isinstance(wanted, dict) else wanted
        return any(_term(v, wanted) for v in _values(doc, name))
    if kind == 'terms':
        name, wanted = next(iter(body.items()))
        return any(_term(v, w) for v in _values(doc, name) for w in wanted)
    if kind == 'wildcard':
        name, spec = next(iter(body.items()))
        flags = re.DOTALL | (re.IGNORECASE if spec.get('case_insensitive') else 0)
        pattern = re.compile(_wildcard_regex(spec['value']), flags)
        return any(pattern.fullmatch(str(v)) for v in _values(doc, name))
    if kind == 'exists':
        return bool(_values(doc, body['field']))
    if kind == 'range':
        name, spec = next(iter(body.items()))
        return any(_in_range(v, spec) for v in _values(doc, name))
    if kind == 'match_all':
        return True
    raise ValueError(f'unsupported query {kind}')

