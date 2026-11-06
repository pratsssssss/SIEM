"""Loads the catalog: every rule file must be listed in rules.yml, and every entry must have a file."""
import importlib.util
import inspect
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import ecs
from .alerts import CONFIDENCES, SEVERITIES
from .custom import CustomRule
from .sigma_compile import Unsupported, compile_file


class CatalogError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    description: str
    kind: str
    level: str
    confidence: str
    enabled: bool
    interval_seconds: int
    tags: list
    query: dict
    fields: list
    path: str
    group_by: list = field(default_factory=list)
    group_window_seconds: int = 3600
    lookback_seconds: int = 0
    custom: CustomRule | None = None


def _load_custom(path):
    spec = importlib.util.spec_from_file_location(f'siem_rule_{path.stem}', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    found = [c for _, c in inspect.getmembers(module, inspect.isclass) if issubclass(c, CustomRule) and c is not CustomRule and c.__module__ == module.__name__]
    if len(found) != 1:
        raise CatalogError(f'{path.name}: must define exactly one CustomRule')
    return found[0]()


def _sources(root, attack_data):
    found = {}
    for path in sorted((root / 'sigma').rglob('*.yml')):
        try:
            found[path] = compile_file(path, attack_data)
        except Unsupported as error:
            raise CatalogError(f'{path.name}: {error}') from error
    for path in sorted((root / 'custom').glob('*.py')):
        found[path] = _load_custom(path)
    return found


def load(root, include_disabled=True, attack_data=False):
    root = Path(root)
    catalog = yaml.safe_load((root / 'rules.yml').read_text(encoding='utf8'))
    defaults = catalog.get('defaults', {})
    entries = {str(e['id']): e for e in catalog['rules']}
    if len(entries) != len(catalog['rules']):
        raise CatalogError('rules.yml: a rule ID is listed twice')
    rules, seen = [], set()
    for path, source in _sources(root, attack_data).items():
        if source.id in seen:
            raise CatalogError(f'{path.name}: duplicate rule ID')
        seen.add(source.id)
        entry = entries.get(source.id)
        if entry is None:
            raise CatalogError(f'{path.name}: not listed in rules.yml')
        level = entry.get('severity', source.level)
        confidence = entry.get('confidence', defaults.get('confidence', 'medium'))
        interval = int(entry.get('interval_seconds', defaults.get('interval_seconds', 300)))
        if level not in SEVERITIES:
            raise CatalogError(f'{path.name}: severity {level} is not valid')
        if confidence not in CONFIDENCES:
            raise CatalogError(f'{path.name}: confidence {confidence} is not valid')
        if interval < 30:
            raise CatalogError(f'{path.name}: interval_seconds is below 30')
        custom = source if isinstance(source, CustomRule) else None
        group_by = list(entry.get('group_by', []))
        for name in group_by:
            if name not in ecs.KAFKA_SAFE_FIELDS:
                raise CatalogError(f'{path.name}: group_by {name} is not a safe field')
        rule = Rule(
            id=source.id, title=source.title, description=source.description, kind='custom' if custom else 'sigma',
            level=level, confidence=confidence, enabled=bool(entry.get('enabled', True)), interval_seconds=interval,
            tags=list(source.tags), query=custom.query() if custom else source.query,
            fields=list(custom.fields) if custom else list(source.fields), path=str(path), group_by=group_by,
            group_window_seconds=int(entry.get('group_window_seconds', 3600)),
            lookback_seconds=custom.lookback_seconds if custom else 0, custom=custom)
        if include_disabled or rule.enabled:
            rules.append(rule)
    missing = set(entries) - seen
    if missing:
        raise CatalogError(f'rules.yml: no rule file for {sorted(missing)}')
    return rules
