"""Live checks on real OpenSearch, as root in WSL. Uses one temporary index, deleted by exact name.

Runs every Sigma fixture on real OpenSearch and compares with the offline evaluator, then records how
the released backends do on the same data, for D6. Prints counts and the case that differs.
Usage: run_live_parity.py <evidence output json>
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import helpers
import yaml
from helpers import RULES, ROOT
from siem_detector import ecs
from siem_detector.dsl_eval import matches
from siem_detector.rules import load

API = 'https://127.0.0.1:9200'
INDEX = 'siem-dtest-parity'
TEMPLATE = ROOT / 'config' / 'opensearch' / 'siem-windows-template.json'
failures = []


def api(path, body=None, method=None):
    command = ['curl', '-sS', '--max-time', '30', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', f'{API}{path}']
    if method:
        command += ['-X', method]
    if body is not None:
        command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    return json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def load_docs():
    fixtures = yaml.safe_load((ROOT / 'tests' / 'detection' / 'fixtures.yml').read_text(encoding='utf8'))
    rules = [r for r in load(RULES) if r.kind == 'sigma']
    docs, expected = [], []
    for made in rules:
        entry = fixtures[Path(made.path).stem]
        for want, key in ((True, 'match'), (False, 'no_match')):
            for doc in entry[key]:
                expected.append((made, len(docs), want))
                docs.append(doc)
    # The same tokens in different case, for the flat_object field that holds script text.
    docs.append({'event': {'dataset': 'windows.powershell', 'code': '4104'}, 'winlog': {'event_data': {'ScriptBlockText': 'iex (X.downloadSTRING())'}}})
    expected.append((next(r for r in rules if 'ps_suspicious' in r.path), len(docs) - 1, True))
    return rules, docs, expected


def create(docs):
    template = json.loads(TEMPLATE.read_text())['template']
    api(f'/{INDEX}', {'settings': {'index': {'number_of_shards': 1, 'number_of_replicas': 0}}, 'mappings': template['mappings']}, 'PUT')
    lines = []
    for number, doc in enumerate(docs):
        lines += [json.dumps({'index': {'_id': str(number)}}), json.dumps(doc)]
    done = subprocess.run(['curl', '-sS', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', '-H', 'Content-Type: application/x-ndjson', '--data-binary', '@-', f'{API}/{INDEX}/_bulk?refresh=true'],
                          input='\n'.join(lines) + '\n', capture_output=True, text=True, check=True)
    result = json.loads(done.stdout)
    check('every fixture indexed under the real mapping', not result['errors'], len(docs))


def ids(query):
    result = api(f'/{INDEX}/_search', {'size': 1000, '_source': False, 'query': query})
    return {int(hit['_id']) for hit in result['hits']['hits']}


def parity(rules, docs, expected):
    for made in rules:
        real = ids(made.query)
        cases = [(number, want) for rule, number, want in expected if rule is made]
        for number, want in cases:
            name = Path(made.path).stem
            offline = matches(made.query, docs[number])
            online = number in real
            check(f'{name} doc {number}: real OpenSearch gives the expected result', online == want, online)
            check(f'{name} doc {number}: offline evaluator agrees with OpenSearch', online == offline, offline)
        # A rule must not match any fixture written for a different rule's log source.
        stray = [n for n in real if not matches(made.query, docs[n])]
        check(f'{Path(made.path).stem}: nothing matches only on OpenSearch', not stray, stray)


def released(rules, docs, expected):
    """D6 evidence: the released backends on the same rules and documents. Does not affect the run."""
    from sigma.backends.opensearch.opensearch import OpensearchLuceneBackend as OpenSearchLuceneBackend
    from sigma.backends.opensearch.opensearch_ppl import OpenSearchPPLBackend
    from sigma.collection import SigmaCollection
    from siem_detector import sigma_compile as sc
    outcome = {}
    for made in rules:
        text = Path(made.path).read_text(encoding='utf8')
        rule = SigmaCollection.from_yaml(text).rules[0]
        source = sc._logsource(rule)
        name = Path(made.path).stem
        row = {}
        try:
            lucene = OpenSearchLuceneBackend(processing_pipeline=sc._pipeline(rule, source)).convert_rule(rule)[0]
            got = api(f'/{INDEX}/_search', {'size': 1000, '_source': False, 'query': {'bool': {'filter': [*source['filter'], {'query_string': {'query': lucene}}]}}})
            found = {int(h['_id']) for h in got['hits']['hits']} if 'hits' in got else None
            row['lucene'] = 'error' if found is None else sum((n in found) != w for r, n, w in expected if r is made)
        except Exception as error:
            row['lucene'] = f'{type(error).__name__}'
        rule = SigmaCollection.from_yaml(text).rules[0]
        try:
            ppl = OpenSearchPPLBackend(processing_pipeline=sc._pipeline(rule, source)).convert_rule(rule)[0]
            row['ppl_query'] = ppl[:160]
            # The backend names its own index pattern. Only that is changed, and the log source is added.
            where = ' '.join(f"AND `{k}`='{v}'" for f in source['filter'] for k, v in f['term'].items())
            statement = re.sub(r'^source=\S+ \| where ', f'source={INDEX} | where (', ppl, count=1).replace(' | ', ' | ', 1)
            statement = f"{statement}) {where} | fields `_id`"
            got = api('/_plugins/_ppl', {'query': statement}, 'POST')
            if 'error' in got:
                row['ppl'] = 'error: ' + str(got['error'].get('details', got['error']))[:90]
            else:
                found = {int(r[0]) for r in got.get('datarows', [])}
                row['ppl'] = sum((n in found) != w for r, n, w in expected if r is made)
        except Exception as error:
            row['ppl'] = f'{type(error).__name__}'
        outcome[name] = row
    return outcome


def main():
    rules, docs, expected = load_docs()
    create(docs)
    try:
        parity(rules, docs, expected)
        outcome = released(rules, docs, expected)
        Path(sys.argv[1]).write_text(json.dumps(outcome, indent=1))
        wrong = sum(1 for row in outcome.values() if row.get('lucene') != 0)
        print(f"released Lucene: {len(outcome) - wrong} of {len(outcome)} rules fully correct on the fixtures")
        right = sum(1 for row in outcome.values() if row.get('ppl') == 0)
        print(f"released PPL: {right} of {len(outcome)} rules fully correct on the fixtures")
    finally:
        print('cleanup', api(f'/{INDEX}', method='DELETE'))
    print(f'{len(failures)} failed' if failures else 'all passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
