"""Runs the real transforms from the real configuration through the Vector binary, on synthetic fixtures.

Nothing here is real telemetry, and no test here reaches Kafka or OpenSearch. Run as any user in WSL.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VECTOR = '/opt/vector/bin/vector'
AGENT = ROOT / 'config' / 'wsl' / 'vector' / 'vector-linux-agent.yaml'
AGGREGATOR = ROOT / 'config' / 'wsl' / 'vector' / 'vector-aggregator.yaml'
ENC, MAC = '11' * 32, '22' * 32
MACHINE = 'ab' * 16
ENV = {'SIEM_LINUX_HOST': 'testhost-wsl', 'SIEM_LINUX_MACHINE': MACHINE, 'NAME': 'Ubuntu', 'VERSION_ID': '24.04'}
STAMP = '2026-11-01T10:00:00.000000Z'


def run_transforms(transforms, inputs, events, secrets=None, parse_time=False):
    """Sends events through the named transforms, and returns what comes out of `inputs`, as dictionaries."""
    with tempfile.TemporaryDirectory() as folder:
        data = Path(folder) / 'data'
        data.mkdir()
        output = Path(folder) / 'out.ndjson'
        config = {'data_dir': str(data), 'sources': {'fixture': {'type': 'file', 'include': [str(Path(folder) / 'in.ndjson')], 'read_from': 'beginning', 'max_line_bytes': 4194304}},
                  'transforms': {'decode': {'type': 'remap', 'inputs': ['fixture'], 'source': '. = object!(parse_json!(string!(.message)))' + ('\nif exists(.timestamp) { .timestamp = parse_timestamp!(.timestamp, "%+") }' if parse_time else '')}, **transforms},
                  'sinks': {'out': {'type': 'file', 'inputs': inputs, 'path': str(output), 'encoding': {'codec': 'json'}}}}
        if secrets:
            keys = Path(folder) / 'keys.json'
            keys.write_text(json.dumps(secrets))
            config['secret'] = {'field_keys': {'type': 'file', 'path': str(keys)}}
        (Path(folder) / 'in.ndjson').write_text(''.join(json.dumps(e) + '\n' for e in events))
        path = Path(folder) / 'vector.yaml'
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        process = subprocess.Popen([VECTOR, '--config', str(path), '--quiet'], env={**os.environ, **ENV, 'VECTOR_LOG': 'error'}, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        try:
            for _ in range(120):
                process.poll()
                if process.returncode is not None:
                    raise RuntimeError(process.stderr.read().decode()[:2000])
                if output.exists() and len(output.read_text().splitlines()) >= len(events):
                    break
                subprocess.run(['sleep', '0.25'], check=True)
            subprocess.run(['sleep', '1'], check=True)
        finally:
            process.terminate()
            process.wait(20)
        return [json.loads(line) for line in output.read_text().splitlines()] if output.exists() else []


def agent_transforms():
    config = yaml.safe_load(AGENT.read_text())
    items = config['transforms']
    for name in ('journal_keep', 'catchup_parsed', 'dpkg_keep'):
        items.pop(name)
    items['protect']['inputs'] = ['decode']
    return items


def normalize_transforms():
    config = yaml.safe_load(AGGREGATOR.read_text())
    items = config['transforms']
    return {'normalize_linux': {**items['normalize_linux'], 'inputs': ['decode']}}


def opened(identifier, message, exe=None, event_data=None, channel='linux-journal', level='6', uid=None, timestamp=STAMP):
    """An event in the shape the verifier forwards to the aggregator."""
    data = {'Identifier': identifier, 'Message': message, 'Comm': identifier, 'Pid': '4242', 'Uid': '0', 'Transport': 'syslog', 'HostId': 'cd' * 16, 'BootId': 'ef' * 16, 'Cursor': 's=1;i=2'}
    if exe:
        data['Exe'] = exe
    data.update(event_data or {})
    return {'channel': channel, 'computer': 'testhost-wsl', 'event_id': 1, 'event_uid': uid or (format(abs(hash((identifier, message, exe))), 'x') * 8)[:64], 'record_id': '1793500000000000', 'timestamp': timestamp, 'level': level, 'provider_name': identifier,
            'labels': {'event_id_basis': 'source_record', 'source_role': 'wsl_infrastructure', 'protection': 'd22-v1', 'os_name': 'Ubuntu', 'os_version': '24.04'}, 'event_data': data, 'kafka': {'topic': 'siem-raw-logs', 'partition': 0, 'offset': 7}}


def get(event, path):
    node = event
    for part in path.split('.'):
        if not isinstance(node, dict):
            return None
        if path in node:
            return node[path]
        node = node.get(part)
    return node
