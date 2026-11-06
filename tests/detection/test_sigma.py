"""Sigma parsing and conversion. Semantics are checked by evaluating the query, not by comparing text."""
import unittest

import helpers
from siem_detector import ecs
from siem_detector.dsl_eval import matches
from sigma.types import SigmaString
from siem_detector.sigma_compile import Unsupported, _wildcard_text, compile_file, compile_text

HEAD = """title: Test
id: 11111111-2222-4333-8444-555555555555
status: test
description: A test.
author: test
date: 2026-10-31
level: low
logsource:
    product: windows
    category: process_creation
"""


def rule(detection, head=HEAD):
    return compile_text(head + 'detection:\n' + detection)


def proc(line='', image='C:\\Windows\\System32\\cmd.exe', parent=''):
    return {'event': {'dataset': 'windows.sysmon', 'code': '1'}, 'process': {'executable': image, 'command_line': line, 'parent': {'executable': parent}}}


class Semantics(unittest.TestCase):
    def test_matching_ignores_case_by_default(self):
        q = rule("    s:\n        CommandLine|contains: 'DownloadString'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('x DOWNLOADSTRING y')))
        self.assertFalse(matches(q, proc('x Download String y')))

    def test_cased_modifier_keeps_case(self):
        q = rule("    s:\n        CommandLine|cased|contains: 'Abc'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('xAbcx')))
        self.assertFalse(matches(q, proc('xABCx')))

    def test_exact_value_must_match_whole_field(self):
        q = rule("    s:\n        CommandLine: 'whoami'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('WHOAMI')))
        self.assertFalse(matches(q, proc('whoami /all')))

    def test_startswith_and_endswith_are_anchored(self):
        q = rule("    s:\n        Image|endswith: '\\cmd.exe'\n    condition: s\n").query
        self.assertTrue(matches(q, proc()))
        self.assertFalse(matches(q, proc(image='C:\\cmd.exe.bak')))
        q = rule("    s:\n        Image|startswith: 'C:\\Windows'\n    condition: s\n").query
        self.assertFalse(matches(q, proc(image='D:\\C:\\Windows\\a')))

    def test_list_means_or_and_all_means_and(self):
        q = rule("    s:\n        CommandLine|contains:\n            - 'a1'\n            - 'b2'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('b2')))
        q = rule("    s:\n        CommandLine|contains|all:\n            - 'a1'\n            - 'b2'\n    condition: s\n").query
        self.assertFalse(matches(q, proc('b2')))
        self.assertTrue(matches(q, proc('b2 a1')))

    def test_condition_logic(self):
        q = rule("    a:\n        CommandLine|contains: 'one'\n    b:\n        CommandLine|contains: 'two'\n    c:\n        CommandLine|contains: 'three'\n    condition: (a or b) and not c\n").query
        self.assertTrue(matches(q, proc('two')))
        self.assertFalse(matches(q, proc('two three')))
        self.assertFalse(matches(q, proc('four')))

    def test_of_conditions(self):
        q = rule("    sel_a:\n        CommandLine|contains: 'one'\n    sel_b:\n        CommandLine|contains: 'two'\n    condition: all of sel_*\n").query
        self.assertFalse(matches(q, proc('one')))
        self.assertTrue(matches(q, proc('one two')))
        q = rule("    sel_a:\n        CommandLine|contains: 'one'\n    sel_b:\n        CommandLine|contains: 'two'\n    condition: 1 of sel_*\n").query
        self.assertTrue(matches(q, proc('two')))

    def test_star_question_mark_and_backslash_stay_literal_once_escaped(self):
        value = SigmaString('a\\*b\\?c\\\\d')
        spec = {'wildcard': {'f': {'value': _wildcard_text(value), 'case_insensitive': True}}}
        self.assertTrue(matches(spec, {'f': 'a*b?c\\d'}))
        self.assertFalse(matches(spec, {'f': 'aXb?c\\d'}))

    def test_official_validation_refuses_a_probably_mistaken_escape(self):
        with self.assertRaisesRegex(Unsupported, 'EscapedWildcard'):
            rule("    s:\n        CommandLine|contains: 'a\\*b'\n    condition: s\n")

    def test_wildcards_in_values_work(self):
        q = rule("    s:\n        CommandLine: 'a*c?e'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('aXXcde')))
        self.assertFalse(matches(q, proc('aXXcdde')))

    def test_windash_modifier_expands(self):
        q = rule("    s:\n        CommandLine|windash|contains: ' -enc '\n    condition: s\n").query
        self.assertTrue(matches(q, proc('x /enc y')))

    def test_base64offset_modifier_expands(self):
        q = rule("    s:\n        CommandLine|base64offset|contains: 'hello'\n    condition: s\n").query
        self.assertTrue(matches(q, proc('aGVsbG8=')))

    def test_log_source_is_always_part_of_the_query(self):
        q = rule("    s:\n        CommandLine|contains: 'x'\n    condition: s\n").query
        other = proc('x')
        other['event']['code'] = '3'
        self.assertFalse(matches(q, other))

    def test_numeric_and_cidr_fields(self):
        head = HEAD.replace('process_creation', 'network_connection')
        q = rule("    s:\n        DestinationPort: 443\n    condition: s\n", head).query
        doc = {'event': {'dataset': 'windows.sysmon', 'code': '3'}, 'destination': {'ip': '10.1.2.3', 'port': 443}}
        self.assertTrue(matches(q, doc))
        q = rule("    s:\n        DestinationIp|cidr: '10.0.0.0/8'\n    condition: s\n", head).query
        self.assertTrue(matches(q, doc))
        q = rule("    s:\n        DestinationPort|gt: 1000\n    condition: s\n", head).query
        self.assertFalse(matches(q, doc))

    def test_event_id_number_becomes_the_stored_string(self):
        head = HEAD.replace('    category: process_creation', '    service: system')
        q = rule("    s:\n        EventID: 7045\n    condition: s\n", head).query
        self.assertTrue(matches(q, {'event': {'dataset': 'windows.system', 'code': '7045'}}))

    def test_used_fields_are_reported_for_evidence(self):
        compiled = rule("    s:\n        CommandLine|contains: 'x'\n        Image|endswith: '\\y'\n    condition: s\n")
        self.assertEqual(compiled.fields, ['process.command_line.keyword', 'process.executable'])


class Refusals(unittest.TestCase):
    """Each of these would change a rule's meaning, or match nothing, if it were accepted."""

    def refused(self, detection, head=HEAD, says=''):
        with self.assertRaises(Unsupported) as caught:
            rule(detection, head)
        self.assertIn(says, str(caught.exception))

    def test_regular_expressions(self):
        self.refused("    s:\n        CommandLine|re: 'a.*b'\n    condition: s\n", says='re modifier')

    def test_field_references(self):
        self.refused("    s:\n        CommandLine|fieldref: Image\n    condition: s\n", says='fieldref')

    def test_keyword_search(self):
        self.refused("    keywords:\n        - 'mimi'\n    condition: keywords\n", says='keyword search')

    def test_field_this_pipeline_does_not_store(self):
        self.refused("    s:\n        NoSuchField: 'x'\n    condition: s\n", says='not stored')

    def test_field_valid_elsewhere_but_not_for_this_source(self):
        self.refused("    s:\n        ScriptBlockText|contains: 'x'\n    condition: s\n", says='not stored')

    def test_log_source_that_is_not_collected(self):
        head = HEAD.replace('    category: process_creation', '    category: driver_load')
        self.refused("    s:\n        ImageLoaded: 'x'\n    condition: s\n", head, says='not collected')

    def test_linux_log_source(self):
        head = HEAD.replace('product: windows', 'product: linux')
        self.refused("    s:\n        Image: 'x'\n    condition: s\n", head, says='not collected')

    def test_wildcard_on_an_ip_field(self):
        head = HEAD.replace('process_creation', 'network_connection')
        self.refused("    s:\n        DestinationIp|startswith: '10.'\n    condition: s\n", head, says='wildcard on IP')

    def test_text_on_a_numeric_field(self):
        head = HEAD.replace('process_creation', 'network_connection')
        self.refused("    s:\n        DestinationPort|contains: '44'\n    condition: s\n", head, says='numeric field')

    def test_numeric_comparison_on_text(self):
        self.refused("    s:\n        CommandLine|gt: 5\n    condition: s\n", says='non-numeric')

    def test_null_on_event_data(self):
        self.refused("    s:\n        IntegrityLevel: null\n    condition: s\n", says='not proven')

    def test_correlation_rule(self):
        text = "title: C\nid: 11111111-2222-4333-8444-555555555556\ncorrelation:\n    type: event_count\n    rules:\n        - base\n    group-by:\n        - User\n    timespan: 5m\n    condition:\n        gte: 5\n"
        base = HEAD.replace('id: 1111', 'name: base\nid: 2222') + "detection:\n    s:\n        Image: 'x'\n    condition: s\n---\n"
        with self.assertRaises(Unsupported):
            compile_text(base + text)

    def test_missing_id(self):
        with self.assertRaises(Exception):
            compile_text(HEAD.replace('id: 11111111-2222-4333-8444-555555555555\n', '') + "detection:\n    s:\n        Image: 'x'\n    condition: s\n")

    def test_missing_level(self):
        with self.assertRaises(Unsupported):
            compile_text(HEAD.replace('level: low\n', '') + "detection:\n    s:\n        Image: 'x'\n    condition: s\n")

    def test_broken_condition(self):
        with self.assertRaises(Exception):
            rule("    s:\n        Image: 'x'\n    condition: nosuchselection\n")

    def test_unused_selection_fails_official_validation(self):
        self.refused("    s:\n        Image: 'x'\n    unused:\n        Image: 'y'\n    condition: s\n", says='Issue')

    def test_invalid_modifier(self):
        with self.assertRaises(Exception):
            rule("    s:\n        Image|nosuchmodifier: 'x'\n    condition: s\n")


class RealRules(unittest.TestCase):
    def test_every_rule_compiles_with_a_case_insensitive_query(self):
        paths = sorted((helpers.RULES / 'sigma').rglob('*.yml'))
        self.assertEqual(len(paths), 24)
        for path in paths:
            compiled = compile_file(path)
            self.assertTrue(compiled.tags)
            self.assertIn(compiled.level, ('low', 'medium', 'high'))

    def test_every_mapped_field_is_a_field_the_index_can_search(self):
        for source in ecs.LOGSOURCES.values():
            for target in source['fields'].values():
                self.assertNotEqual(target, 'process.command_line', 'the analyzed field cannot match a substring')
                self.assertNotEqual(target, 'powershell.script_block.text', 'the analyzed field cannot match a substring')


if __name__ == '__main__':
    unittest.main()
