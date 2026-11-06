"""Extraction, normalization, and the gate on what may leave the host."""
import unittest

import helpers  # noqa: F401
from siem_enricher import indicators as ind
from siem_enricher.indicators import DOMAIN, HASH, IP, URL, Indicator


class IPs(unittest.TestCase):
    def test_normal_forms(self):
        self.assertEqual(ind.normalize_ip(' 8.8.8.8 '), '8.8.8.8')
        self.assertEqual(ind.normalize_ip('2001:4860:4860:0:0:0:0:8888'), '2001:4860:4860::8888')
        self.assertEqual(ind.normalize_ip('::ffff:8.8.8.8'), '8.8.8.8')
        self.assertEqual(ind.normalize_ip('[2606:4700::1111]'), '2606:4700::1111')

    def test_rejects_non_addresses(self):
        for text in ('8.8.8', '999.1.1.1', 'example.com', '', '8.8.8.8.8', '1.2.3.4/24'):
            self.assertIsNone(ind.normalize_ip(text), text)

    def test_public_addresses(self):
        for text in ('8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'):
            self.assertTrue(ind.is_public_ip(text), text)

    def test_every_private_or_reserved_range_is_excluded(self):
        for text in ('10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '169.254.1.1', '0.0.0.0', '100.64.0.1', '192.0.2.1', '198.51.100.1', '203.0.113.1',
                     '224.0.0.1', '239.255.255.250', '255.255.255.255', '240.0.0.1', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '2001:db8::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1'):
            self.assertFalse(ind.is_public_ip(text), text)


class Domains(unittest.TestCase):
    def test_normalizes(self):
        self.assertEqual(ind.normalize_domain('Example.COM.'), 'example.com')
        self.assertEqual(ind.normalize_domain('bücher.example'), 'xn--bcher-kva.example')

    def test_rejects(self):
        for text in ('localhost', '8.8.8.8', '-bad.example.com', 'a..b', 'a b.com', 'x' * 300 + '.com', 'host', '1.2.3.4.5', 'example.123'):
            self.assertIsNone(ind.normalize_domain(text), text)

    def test_internal_names_are_not_public(self):
        for text in ('printer.local', 'dc01.corp', 'nas.lan', 'x.internal', '1.0.168.192.in-addr.arpa', 'router.home', 'a.test'):
            self.assertFalse(ind.is_public_domain(text), text)
        self.assertTrue(ind.is_public_domain('example.com'))


class Urls(unittest.TestCase):
    def test_credentials_are_removed(self):
        self.assertEqual(ind.sanitize_url('https://admin:Secret123@example.com/a'), 'https://example.com/a')

    def test_the_whole_query_is_removed(self):
        for query in ('?token=abc', '?session=1&x=2', '?a=b', '?password=x', '?sig=abc&exp=1'):
            self.assertEqual(ind.sanitize_url('https://example.com/a' + query), 'https://example.com/a', query)

    def test_fragment_is_removed(self):
        self.assertEqual(ind.sanitize_url('https://example.com/a#token=abc'), 'https://example.com/a')

    def test_case_and_default_ports(self):
        self.assertEqual(ind.sanitize_url('HTTP://EXAMPLE.com:80/Path'), 'http://example.com/Path')
        self.assertEqual(ind.sanitize_url('https://example.com:8443'), 'https://example.com:8443/')

    def test_ip_host(self):
        self.assertEqual(ind.sanitize_url('http://8.8.8.8/x'), 'http://8.8.8.8/x')

    def test_rejects_other_schemes_and_junk(self):
        for text in ('file:///etc/passwd', 'javascript:alert(1)', 'mailto:a@example.com', 'http://', 'not a url', 'http://exa mple.com/', 'https://example.com/' + 'a' * 3000, 'http://a\x00b.example.com/', 'http://host/'):
            self.assertIsNone(ind.sanitize_url(text), text)

    def test_trailing_punctuation_from_prose(self):
        self.assertEqual(ind.sanitize_url('http://example.com/a).'), 'http://example.com/a')


class Hashes(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ind.normalize_hash('AB' * 32), 'ab' * 32)

    def test_invalid(self):
        for text in ('ab' * 31, 'ab' * 33, 'z' * 64, '', 'd41d8cd98f00b204e9800998ecf8427e', 'ab' * 20):
            self.assertIsNone(ind.normalize_hash(text), text)


class Extraction(unittest.TestCase):
    def keys(self, doc):
        return {i.key: i for i in ind.extract(doc)}

    def test_network_event(self):
        found = self.keys({'destination': {'ip': '8.8.8.8'}, 'source': {'ip': '10.0.0.5'}})
        self.assertIn((IP, '8.8.8.8'), found)
        self.assertFalse(found[(IP, '8.8.8.8')].restricted)

    def test_dns_event_and_its_answers(self):
        found = self.keys({'dns': {'question': {'name': 'Example.COM'}, 'answers': {'data': '::ffff:93.184.216.34;8.8.4.4;'}}})
        self.assertIn((DOMAIN, 'example.com'), found)
        self.assertIn((IP, '8.8.4.4'), found)

    def test_process_hash(self):
        found = self.keys({'process': {'hash': {'sha256': 'AB' * 32}}})
        self.assertIn((HASH, 'ab' * 32), found)

    def test_command_line_values_are_marked_restricted(self):
        found = self.keys({'process': {'command_line': 'curl http://bad.example.com/a?token=SECRET 8.8.8.8'}})
        self.assertTrue(found[(URL, 'http://bad.example.com/a')].restricted)
        self.assertTrue(found[(DOMAIN, 'bad.example.com')].restricted)
        self.assertTrue(found[(IP, '8.8.8.8')].restricted)

    def test_secret_never_survives_extraction(self):
        items = ind.extract({'process': {'command_line': 'tool https://user:hunter2@example.com/x?key=SECRET#frag'}})
        self.assertNotIn('hunter2', str(items))
        self.assertNotIn('SECRET', str(items))

    def test_structured_sighting_clears_the_restricted_mark(self):
        found = self.keys({'destination': {'ip': '8.8.8.8'}, 'process': {'command_line': 'ping 8.8.8.8'}})
        self.assertFalse(found[(IP, '8.8.8.8')].restricted)

    def test_duplicates_collapse(self):
        self.assertEqual(len(ind.extract({'process': {'command_line': 'http://a.example.com/x http://a.example.com/x http://a.example.com/x'}})), 2)

    def test_alert_evidence(self):
        alert = {'evidence': {'matched_fields': {'destination.ip': ['8.8.8.8'], 'process.command_line': ['x http://bad.example.com/y'], 'user.name': ['bob'], 'dns.question.name': ['evil.example.com']}}}
        found = {i.key: i for i in ind.extract_alert(alert)}
        self.assertFalse(found[(IP, '8.8.8.8')].restricted)
        self.assertTrue(found[(URL, 'http://bad.example.com/y')].restricted)
        self.assertIn((DOMAIN, 'evil.example.com'), found)
        self.assertNotIn('bob', str(found))

    def test_withheld_digests_are_ignored(self):
        alert = {'evidence': {'matched_fields': {'process.command_line': [{'withheld': True, 'sha256': 'ab' * 32, 'length': 9}]}}}
        self.assertEqual(ind.extract_alert(alert), [])

    def test_garbage_is_ignored(self):
        self.assertEqual(ind.extract({'destination': {'ip': 'not-an-ip'}, 'process': {'hash': {'sha256': 'short'}}}), [])
        self.assertEqual(ind.extract_alert({}), [])

    def test_guess_for_the_manual_command(self):
        self.assertEqual(ind.guess('8.8.8.8').kind, IP)
        self.assertEqual(ind.guess('example.com').kind, DOMAIN)
        self.assertEqual(ind.guess('https://example.com/a').kind, URL)
        self.assertEqual(ind.guess('ab' * 32).kind, HASH)
        self.assertIsNone(ind.guess('nonsense'))


class Gate(unittest.TestCase):
    def test_public_structured_values_pass(self):
        for item in (Indicator(IP, '8.8.8.8'), Indicator(DOMAIN, 'example.com'), Indicator(HASH, 'ab' * 32)):
            self.assertTrue(ind.external_allowed(item), item)

    def test_private_addresses_never_pass(self):
        for value in ('10.0.0.1', '192.168.1.1', '127.0.0.1', 'fe80::1', '198.51.100.7'):
            self.assertFalse(ind.external_allowed(Indicator(IP, value)), value)

    def test_internal_names_never_pass(self):
        self.assertFalse(ind.external_allowed(Indicator(DOMAIN, 'dc01.corp')))

    def test_anything_from_restricted_text_never_passes(self):
        for item in (Indicator(IP, '8.8.8.8', restricted=True), Indicator(DOMAIN, 'example.com', restricted=True), Indicator(URL, 'https://example.com/', restricted=True)):
            self.assertFalse(ind.external_allowed(item, allow_urls=True), item)

    def test_urls_stay_home_by_default(self):
        self.assertFalse(ind.external_allowed(Indicator(URL, 'https://example.com/a')))
        self.assertTrue(ind.external_allowed(Indicator(URL, 'https://example.com/a'), allow_urls=True))

    def test_an_unsanitized_url_is_refused_even_when_allowed(self):
        self.assertFalse(ind.external_allowed(Indicator(URL, 'https://example.com/a?token=x'), allow_urls=True))

    def test_url_on_an_internal_host_is_refused(self):
        self.assertFalse(ind.external_allowed(Indicator(URL, 'https://dc01.corp/a'), allow_urls=True))

    def test_unknown_kind_is_refused(self):
        self.assertFalse(ind.external_allowed(Indicator('email', 'a@example.com')))


if __name__ == '__main__':
    unittest.main()
