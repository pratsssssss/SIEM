"""Compiles Sigma rules to OpenSearch Query DSL, using the official pySigma parser and validators.

The released Lucene backend is not used, because a Lucene string on a keyword field is case-sensitive
and Sigma matching is not. See docs/adr/0009-detection-engine.md, D6 result. Anything this backend
cannot express exactly raises Unsupported, so a rule is refused rather than changed.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionItem, ConditionNOT, ConditionOR, ConditionValueExpression
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.types import CompareOperators, SigmaCasedString, SigmaCIDRExpression, SigmaCompareExpression, SigmaExists, SigmaNull, SigmaNumber, SigmaString, SpecialChars
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators
from sigma.validators.core.tags import ATTACKTagValidator, D3FENDTagValidator

from . import ecs


class Unsupported(ValueError):
    """The rule uses something that cannot be expressed exactly."""


def _wildcard_text(value: SigmaString) -> str:
    out = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            out.append('*')
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append('?')
        elif isinstance(part, str):
            out.append(part.replace('\\', '\\\\').replace('*', '\\*').replace('?', '\\?'))
        else:
            raise Unsupported(f'unresolved placeholder in {value}')
    return ''.join(out)


class OpenSearchDSL(Backend):
    """Turns a parsed Sigma condition into a bool query. Each convert method refuses what it cannot do."""
    name: ClassVar[str] = 'SIEM OpenSearch Query DSL'
    formats: ClassVar[dict[str, str]] = {'default': 'Query DSL dictionary'}

    def __init__(self, processing_pipeline, allowed):
        super().__init__(processing_pipeline=processing_pipeline, collect_errors=False)
        self.allowed = allowed

    def finalize_query_default(self, rule, query, index, state):
        return query

    def convert_condition(self, cond, state):
        return super().convert_condition(cond, state)

    def decide_convert_condition_as_in_expression(self, cond, state):
        return False

    def convert_condition_as_in_expression(self, cond, state):
        raise Unsupported('in-expressions are not used')

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState):
        return {'bool': {'should': [self.convert_condition(arg, state) for arg in cond.args], 'minimum_should_match': 1}}

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState):
        return {'bool': {'filter': [self.convert_condition(arg, state) for arg in cond.args]}}

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState):
        return {'bool': {'must_not': [self.convert_condition(cond.args[0], state)]}}

    def _field(self, cond) -> tuple[str, str]:
        if cond.field not in self.allowed:
            raise Unsupported(f'field {cond.field} is not stored for this log source')
        return cond.field, ecs.FIELD_TYPES.get(cond.field, 'keyword')

    def _string(self, cond, insensitive):
        name, kind = self._field(cond)
        if kind == 'long':
            text = cond.value.to_plain() if not cond.value.contains_special() else None
            if text is None or not text.isdigit():
                raise Unsupported(f'text pattern on numeric field {name}')
            return {'term': {name: int(text)}}
        if kind == 'ip':
            if cond.value.contains_special():
                raise Unsupported(f'wildcard on IP field {name}. Use the cidr modifier')
            return {'term': {name: cond.value.to_plain()}}
        return {'wildcard': {name: {'value': _wildcard_text(cond.value), 'case_insensitive': insensitive}}}

    def convert_condition_field_eq_val_str(self, cond, state):
        return self._string(cond, True)

    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
        return self._string(cond, False)

    def convert_condition_field_eq_val_num(self, cond, state):
        name, kind = self._field(cond)
        return {'term': {name: cond.value.number if kind == 'long' else str(cond.value.number)}}

    def convert_condition_field_eq_val_cidr(self, cond, state):
        name, kind = self._field(cond)
        if kind != 'ip':
            raise Unsupported(f'cidr on non-IP field {name}')
        return {'term': {name: str(cond.value.network)}}

    def convert_condition_field_compare_op_val(self, cond, state):
        name, kind = self._field(cond)
        if kind != 'long':
            raise Unsupported(f'numeric comparison on non-numeric field {name}')
        operator = {CompareOperators.LT: 'lt', CompareOperators.LTE: 'lte', CompareOperators.GT: 'gt', CompareOperators.GTE: 'gte'}[cond.value.op]
        return {'range': {name: {operator: cond.value.number.number}}}

    def _exact_ecs(self, cond):
        name, _ = self._field(cond)
        if name.startswith('winlog.event_data.'):
            raise Unsupported(f'null and exists are not proven on {name}')
        return name

    def convert_condition_field_eq_val_null(self, cond, state):
        return {'bool': {'must_not': [{'exists': {'field': self._exact_ecs(cond)}}]}}

    def convert_condition_field_exists(self, cond, state):
        return {'exists': {'field': self._exact_ecs(cond)}}

    def convert_condition_field_not_exists(self, cond, state):
        return {'bool': {'must_not': [{'exists': {'field': self._exact_ecs(cond)}}]}}

    def convert_condition_field_eq_val_exists(self, cond, state):
        return self.convert_condition_field_exists(cond, state) if cond.value else self.convert_condition_field_not_exists(cond, state)

    def convert_condition_field_eq_val_re(self, cond, state):
        raise Unsupported('the re modifier: Lucene regular expressions are anchored and are not PCRE. Use a custom rule')

    def convert_condition_field_eq_val_bool(self, cond, state):
        raise Unsupported('boolean values: no boolean field is stored')

    def convert_condition_field_eq_val_timestamp_part(self, cond, state):
        raise Unsupported('timestamp modifiers')

    def convert_condition_field_eq_field(self, cond, state):
        raise Unsupported('the fieldref modifier: a query cannot compare two fields')

    def convert_condition_field_eq_query_expr(self, cond, state):
        raise Unsupported('query expressions')

    def convert_condition_val(self, cond, state):
        raise Unsupported('keyword search: a value with no field')

    def convert_condition_val_str(self, cond, state):
        raise Unsupported('keyword search: a value with no field')

    def convert_condition_val_num(self, cond, state):
        raise Unsupported('keyword search: a value with no field')

    def convert_condition_val_re(self, cond, state):
        raise Unsupported('keyword search: a value with no field')

    def convert_condition_query_expr(self, cond, state):
        raise Unsupported('query expressions')


def _refuse(name):
    def refuse(self, *args, **kwargs):
        raise Unsupported(f'{name} is not implemented, so the rule is refused')
    return refuse


# Whatever pySigma can ask for that is not written above, such as correlations, is refused.
for _name in OpenSearchDSL.__abstractmethods__:
    setattr(OpenSearchDSL, _name, _refuse(_name))
OpenSearchDSL.__abstractmethods__ = frozenset()


@dataclass
class CompiledSigma:
    id: str
    title: str
    description: str
    level: str
    tags: list
    query: dict
    fields: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)
    status: str = ''


def _logsource(rule):
    key = (rule.logsource.product, rule.logsource.category, rule.logsource.service)
    if key not in ecs.LOGSOURCES:
        raise Unsupported(f'log source {key} is not collected')
    return ecs.LOGSOURCES[key]


def _pipeline(rule, source):
    mapping = FieldMappingTransformation(dict(source['fields']))
    condition = LogsourceCondition(category=rule.logsource.category, product=rule.logsource.product, service=rule.logsource.service)
    return ProcessingPipeline(name='siem-ecs', items=[ProcessingItem(transformation=mapping, rule_conditions=[condition], identifier='siem-ecs-fields')])


def _used_fields(cond, found):
    if isinstance(cond, ConditionFieldEqualsValueExpression):
        found.add(cond.field)
    elif isinstance(cond, ConditionItem):
        for arg in cond.args:
            _used_fields(arg, found)
    return found


def validate(rule, attack_data=False):
    """Sigma's own checks, on metadata, log source, selections, conditions and modifiers.

    pySigma's tag checks download ATT&CK data from GitHub. They run only when asked for, by
    `validate --attack`, so the service itself never reaches the internet.
    """
    chosen = [v for v in core_validators.values() if attack_data or not issubclass(v, (ATTACKTagValidator, D3FENDTagValidator))]
    return [f'{type(issue).__name__}: {issue.description}' for issue in SigmaValidator(chosen).validate_rule(rule)]


def compile_text(text: str, attack_data=False) -> CompiledSigma:
    collection = SigmaCollection.from_yaml(text, collect_errors=False)
    if len(collection.rules) != 1:
        raise Unsupported('a file must hold exactly one rule')
    rule = collection.rules[0]
    if isinstance(rule, SigmaCorrelationRule):
        raise Unsupported('Sigma correlation rules: write a custom rule, see docs/detection/writing-rules.md')
    if not isinstance(rule, SigmaRule):
        raise Unsupported('not a Sigma detection rule')
    for error in rule.errors:
        raise Unsupported(str(error))
    if not rule.id:
        raise Unsupported('the rule has no id')
    if not rule.level:
        raise Unsupported('the rule has no level')
    issues = validate(rule, attack_data)
    if issues:
        raise Unsupported('; '.join(issues))
    source = _logsource(rule)
    backend = OpenSearchDSL(_pipeline(rule, source), set(source['fields'].values()))
    conditions = backend.convert_rule(rule)
    if not conditions:
        raise Unsupported('the rule has no condition')
    used = set()
    for parsed in rule.detection.parsed_condition:
        _used_fields(parsed.parsed, used)
    body = conditions[0] if len(conditions) == 1 else {'bool': {'should': conditions, 'minimum_should_match': 1}}
    query = {'bool': {'filter': [*source['filter'], body]}}
    return CompiledSigma(
        id=str(rule.id), title=rule.title, description=rule.description or '', level=rule.level.name.lower(),
        tags=[str(tag) for tag in rule.tags], query=query, fields=sorted(used), falsepositives=list(rule.falsepositives or []),
        status=rule.status.name.lower() if rule.status else '')


def compile_file(path: Path, attack_data=False) -> CompiledSigma:
    try:
        return compile_text(Path(path).read_text(encoding='utf8'), attack_data)
    except SigmaError as error:
        raise Unsupported(str(error)) from error
