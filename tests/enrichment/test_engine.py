"""Feeds, the lookup path, the service, and the ten required use cases."""
import json
import threading
import unittest

import helpers
from helpers import BAD_DOMAIN, BAD_HASH, BAD_IP, BAD_URL, NOW, OTHER_IP, FakeOpenSearch, FakeWeb, Reply, World, web_error
from siem_enricher import feeds as feed_lib
from siem_enricher import indicators as ind
from siem_enricher import providers as p
from siem_enricher import score, service
from siem_enricher.indicators import DOMAIN, HASH, IP, URL, Indicator
from siem_enricher.score import HIT, NO_MATCH, Observation

MIN = 60000
HOUR = 3600000


class Canned(p.Provider):
    """A provider with a scripted answer, counting its calls."""
    host = 'api.example.com'
    kinds = ind.KINDS
    needs_key = False
    per_minute, per_day = 1000, 100000

    def __init__(self, name='canned', answer=None, publisher=None):
        super().__init__()
        self.name = name
        self.publisher = publisher or name
        self.answer = answer
        self.quality = 0.85
        self.calls = []
        self.lock = threading.Lock()

    def query(self, web, kind, value):
        with self.lock:
            self.calls.append((kind, value))
        result = self.answer(self) if callable(self.answer) else self.answer
        if isinstance(result, Exception):
            raise result
        return result


def bad(provider):
    return provider._observe(HIT, stance='malicious', confidence=95)


def clean(provider):
    return provider._observe(NO_MATCH)


def good(provider):
    return provider._observe(HIT, stance='benign', confidence=90)


class Feeds(unittest.TestCase):
    def test_plain_list_with_comments_and_junk(self):
        w = World(self)
        w.feed_file('f', f'# comment\n{BAD_IP}\nnot-an-ip\n\n{OTHER_IP} ; note\n10.0.0.0/8\n', stale_hours=24)
        self.assertEqual(w.store.feed_state('f')['rows'], 3)
        self.assertTrue(w.store.intel(IP, BAD_IP))

    def test_cidr_ranges_match_inside_and_not_outside(self):
        w = World(self)
        feed = w.feed_file('f', '8.8.8.0/24\n')
        self.assertEqual(w.feeds.lookup(IP, '8.8.8.200')[0].status, HIT)
        self.assertEqual(w.feeds.lookup(IP, '8.8.9.1')[0].status, NO_MATCH)
        self.assertEqual(feed.name, 'f')

    def test_owner_file_format(self):
        w = World(self)
        w.feed_file('own', f'sha256,{BAD_HASH},TestFamily\ndomain,{BAD_DOMAIN},c2\nurl,{BAD_URL}?x=1,phish\nip,8.8.4.0/24,bad\nbogus,row\n', format='indicators', kind=HASH)
        self.assertEqual(w.store.intel(HASH, BAD_HASH)[0]['category'], 'TestFamily')
        self.assertTrue(w.store.intel(URL, BAD_URL))
        self.assertEqual(w.store.feed_state('own')['rows'], 4)

    def test_feodo_and_spamhaus_and_cloud_formats(self):
        for form, body, kind in (('feodo-json', json.dumps([{'ip_address': BAD_IP, 'malware': 'Emotet', 'first_seen': '2026-01-01 00:00:00', 'last_online': '2026-10-01'}]), IP),
                                 ('spamhaus-jsonl', '{"cidr":"8.8.4.0/24","sblid":"S"}\n{"type":"metadata"}\n', IP),
                                 ('aws-json', json.dumps({'prefixes': [{'ip_prefix': '8.8.4.0/24'}], 'ipv6_prefixes': [{'ipv6_prefix': '2600::/16'}]}), IP),
                                 ('gcp-json', json.dumps({'prefixes': [{'ipv4Prefix': '8.8.4.0/24'}]}), IP)):
            w = World(self)
            w.feed_file('f', body, format=form, kind=kind)
            self.assertEqual(w.feeds.lookup(IP, BAD_IP)[0].status, HIT, form)

    def test_domain_matches_subdomains_not_parents(self):
        w = World(self)
        w.feed_file('d', 'evil.example.com\n', kind=DOMAIN)
        self.assertEqual(w.feeds.lookup(DOMAIN, 'a.b.evil.example.com')[0].status, HIT)
        self.assertEqual(w.feeds.lookup(DOMAIN, 'example.com')[0].status, NO_MATCH)
        self.assertEqual(w.feeds.lookup(DOMAIN, 'notevil.example.com')[0].status, NO_MATCH)

    def test_url_is_also_checked_against_domain_feeds(self):
        w = World(self)
        w.feed_file('d', 'evil.example.com\n', kind=DOMAIN)
        self.assertEqual(w.feeds.lookup(URL, 'http://evil.example.com/x')[0].status, HIT)

    def test_web_page_instead_of_a_feed_keeps_old_data(self):
        web = FakeWeb([Reply(f'{BAD_IP}\n{OTHER_IP}\n'.encode(), headers={'ETag': 'x'}), Reply(b'<!DOCTYPE html><html>sorry</html>')])
        w = World(self, web=web)
        feed = feed_lib.Feed(name='f', format='lines', kind=IP, publisher='f', url='https://x.example/f')
        w.feeds.feeds.append(feed)
        w.feeds.update(feed)
        self.assertIn('failed', w.feeds.update(feed, force=True))
        self.assertTrue(w.store.intel(IP, BAD_IP))

    def test_collapsed_feed_is_refused(self):
        w = World(self)
        body = ''.join(f'8.8.{i}.{j}\n' for i in range(3) for j in range(100))
        feed = w.feed_file('f', body)
        (w.folder / 'f.txt').write_text('8.8.0.1\n')
        self.assertIn('down from', w.feeds.update(feed))
        self.assertEqual(w.store.feed_state('f')['rows'], 300)

    def test_too_few_rows_is_refused(self):
        w = World(self)
        feed = w.feed_file('f', BAD_IP + '\n', min_rows=5)
        self.assertEqual(w.store.feed_state('f')['rows'], 0)
        self.assertIn('only 1', w.store.feed_state(feed.name)['last_error'])

    def test_outage_keeps_old_data_and_records_the_error(self):
        web = FakeWeb([Reply(f'{BAD_IP}\n'.encode()), web_error(503)])
        w = World(self, web=web)
        feed = feed_lib.Feed(name='f', format='lines', kind=IP, publisher='f', url='https://x.example/f')
        w.feeds.feeds.append(feed)
        w.feeds.update(feed)
        w.feeds.update(feed, force=True)
        self.assertTrue(w.store.intel(IP, BAD_IP))
        self.assertIn('503', w.store.feed_state('f')['last_error'])

    def test_conditional_request_and_unchanged_answer(self):
        web = FakeWeb([Reply(f'{BAD_IP}\n'.encode(), headers={'ETag': '"v1"'}), Reply(b'', 304)])
        w = World(self, web=web)
        feed = feed_lib.Feed(name='f', format='lines', kind=IP, publisher='f', url='https://x.example/f')
        w.feeds.feeds.append(feed)
        w.feeds.update(feed)
        self.assertEqual(w.feeds.update(feed), 'unchanged')
        self.assertEqual(web.requests[1]['headers']['If-None-Match'], '"v1"')

    def test_incremental_pull_keeps_first_seen_and_drops_removed_rows(self):
        w = World(self)
        feed = w.feed_file('f', f'sha256,{BAD_HASH}\n', format='indicators', kind=HASH)
        w.store.db.execute("UPDATE intel SET first_seen = '2026-01-01T00:00:00Z'")
        (w.folder / 'f.txt').write_text(f'sha256,{BAD_HASH}\nsha256,{"b" * 64}\n')
        w.feeds.update(feed)
        self.assertEqual(w.store.intel(HASH, BAD_HASH)[0]['first_seen'], '2026-01-01T00:00:00Z')
        (w.folder / 'f.txt').write_text(f'sha256,{"b" * 64}\n')
        w.feeds.update(feed)
        self.assertEqual(w.store.intel(HASH, BAD_HASH), [])

    def test_stale_feed_cannot_say_clean(self):
        w = World(self)
        w.feed_file('f', BAD_IP + '\n', stale_hours=1)
        w.clock.now += 2 * HOUR
        result = w.engine.lookup([Indicator(IP, OTHER_IP)])[(IP, OTHER_IP)]
        self.assertEqual(result['verdict'], score.UNKNOWN)

    def test_due_respects_the_refresh_interval(self):
        w = World(self)
        feed = w.feed_file('f', BAD_IP + '\n', refresh_hours=24)
        self.assertEqual(w.feeds.due(), [])
        w.clock.now += 25 * HOUR
        self.assertEqual(w.feeds.due(), [feed])

    def test_disabled_feed_is_ignored(self):
        w = World(self)
        w.feed_file('f', BAD_IP + '\n', enabled=False)
        self.assertEqual(w.feeds.lookup(IP, BAD_IP), [])


class OwnerFiles(unittest.TestCase):
    def test_every_csv_in_the_folder_becomes_a_feed(self):
        w = World(self)
        folder = w.folder / 'owner'
        folder.mkdir()
        (folder / 'mine.csv').write_text(f'sha256,{BAD_HASH},Family\ndomain,{BAD_DOMAIN},c2\nip,{BAD_IP},bad\nurl,{BAD_URL},x\n')
        found = feed_lib.owner_files(folder)
        self.assertEqual([f.name for f in found], ['owner-mine'])
        w.feeds.feeds.extend(found)
        w.feeds.update(found[0])
        for kind, value in ((HASH, BAD_HASH), (DOMAIN, BAD_DOMAIN), (IP, BAD_IP), (URL, BAD_URL)):
            result = w.engine.lookup([Indicator(kind, value)])[(kind, value)]
            self.assertEqual(result['verdict'], score.MALICIOUS, kind)
            self.assertEqual(result['sources'][0]['source'], 'owner-mine')

    def test_purge_removes_a_feed_entirely(self):
        w = World(self)
        w.feed_file('f', '8.8.8.0/24\n1.0.0.1\n')
        self.assertEqual(w.store.purge_feed('f'), 2)
        self.assertEqual(w.store.feed_state('f')['rows'], 0)
        self.assertEqual(w.store.intel(IP, '1.0.0.1'), [])

    def test_a_miss_in_an_owner_file_says_nothing(self):
        w = World(self)
        w.feed_file('own', f'sha256,{BAD_HASH},x\n', format='indicators', kind=HASH)
        other = 'b' * 64
        self.assertEqual(w.engine.lookup([Indicator(HASH, other)])[(HASH, other)]['verdict'], score.UNKNOWN)

    def test_synthetic_files_are_marked(self):
        w = World(self)
        folder = w.folder / 'owner'
        folder.mkdir()
        (folder / 'synthetic-test.csv').write_text(f'ip,{BAD_IP}\n')
        self.assertTrue(feed_lib.owner_files(folder)[0].synthetic)

    def test_a_missing_folder_is_no_feeds(self):
        self.assertEqual(feed_lib.owner_files('/nonexistent'), [])
        self.assertEqual(feed_lib.owner_files(None), [])


class Heuristics(unittest.TestCase):
    def test_signals(self):
        self.assertIn('punycode', feed_lib.domain_signals('xn--pypal-4ve.example.com'))
        self.assertIn('high-entropy-label', feed_lib.domain_signals('qx7f9k2m4v8z1p3w6r5t.example'))
        self.assertIn('many-labels', feed_lib.domain_signals('a.b.c.d.e.f.example.com'))
        self.assertEqual(feed_lib.domain_signals('example.com'), [])

    def test_alone_they_never_make_a_finding(self):
        w = World(self)
        result = w.engine.lookup([Indicator(DOMAIN, 'qx7f9k2m4v8z1p3w6r5t.example')])
        self.assertEqual(result[(DOMAIN, 'qx7f9k2m4v8z1p3w6r5t.example')]['verdict'], score.UNKNOWN)
        self.assertEqual(result[(DOMAIN, 'qx7f9k2m4v8z1p3w6r5t.example')]['sources'][0]['source'], 'domain-heuristics')


class Lookups(unittest.TestCase):
    def test_no_external_call_unless_asked(self):
        provider = Canned(answer=bad)
        World(self, providers=[provider]).engine.lookup([Indicator(IP, BAD_IP)], external=False)
        self.assertEqual(provider.calls, [])

    def test_cache_hit_makes_no_second_call(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        first = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        second = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(first[(IP, BAD_IP)]['verdict'], second[(IP, BAD_IP)]['verdict'])
        self.assertEqual(w.store.counters()['cache_hit'], 1)

    def test_cache_survives_a_restart(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        from siem_enricher.engine import Engine
        again = Engine(w.store, w.feeds, None, {'canned': provider}, w.web, clock=w.clock, log=lambda t: None)
        again.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)

    def test_clean_answers_are_cached_for_less_time_than_findings(self):
        provider = Canned(answer=clean)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        w.clock.now += 5 * HOUR
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)
        w.clock.now += 2 * HOUR
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 2)

    def test_expiry_and_ttl_by_kind(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(HASH, BAD_HASH)], external=True)
        w.clock.now += 29 * 24 * HOUR
        w.engine.lookup([Indicator(HASH, BAD_HASH)], external=True)
        self.assertEqual(len(provider.calls), 1)
        w.clock.now += 2 * 24 * HOUR
        w.engine.lookup([Indicator(HASH, BAD_HASH)], external=True)
        self.assertEqual(len(provider.calls), 2)

    def test_invalidation(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP), Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(w.store.cache_clear(value=BAD_IP), 1)
        w.engine.lookup([Indicator(IP, BAD_IP), Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(len(provider.calls), 3)
        self.assertEqual(w.store.cache_clear(provider='canned'), 2)

    def test_failure_is_not_cached(self):
        provider = Canned(answer=helpers.WebError('HTTP 400', 400))
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        provider.answer = bad
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(result[(IP, BAD_IP)]['verdict'], score.MALICIOUS)

    def test_repeats_in_one_batch_make_one_request(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)] * 50, external=True)
        self.assertEqual(len(provider.calls), 1)

    def test_workers_are_bounded(self):
        active, peak = [0], [0]
        guard = threading.Lock()

        def slow(provider):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            threading.Event().wait(0.02)
            with guard:
                active[0] -= 1
            return clean(provider)
        provider = Canned(answer=slow)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, f'8.8.{i}.1') for i in range(20)], external=True)
        self.assertLessEqual(peak[0], w.engine.limits.workers)
        self.assertGreater(peak[0], 1)

    def test_per_minute_limit_marks_rate_limited(self):
        provider = Canned(answer=clean)
        provider.per_minute = 2
        w = World(self, providers=[provider])
        items = [Indicator(IP, f'8.8.{i}.1') for i in range(4)]
        results = w.engine.lookup(items, external=True)
        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(sum(r['verdict'] == score.LOOKUP_FAILED for r in results.values()), 2)
        w.clock.now += MIN + 1
        w.engine.lookup(items, external=True)
        self.assertEqual(len(provider.calls), 4)

    def test_daily_quota_persists_and_resets_next_day(self):
        provider = Canned(answer=clean)
        provider.per_day = 1
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        result = w.engine.lookup([Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(result[(IP, OTHER_IP)]['verdict'], score.LOOKUP_FAILED)
        w.clock.now += 25 * HOUR
        w.engine.lookup([Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(len(provider.calls), 2)

    def test_retry_with_exponential_backoff_then_success(self):
        answers = [web_error(503), web_error(None), None]

        def flaky(provider):
            value = answers.pop(0)
            return value or bad(provider)
        provider = Canned(answer=flaky)
        w = World(self, providers=[provider])
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(result[(IP, BAD_IP)]['verdict'], score.MALICIOUS)
        self.assertEqual(w.slept, [2.0, 4.0])

    def test_timeouts_retry_then_are_marked_failed(self):
        provider = Canned(answer=helpers.WebError('TimeoutError'))
        w = World(self, providers=[provider])
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(result[(IP, BAD_IP)]['verdict'], score.LOOKUP_FAILED)
        self.assertEqual(len(provider.calls), 3)

    def test_rate_limit_from_the_provider_pauses_it_for_retry_after(self):
        provider = Canned(answer=web_error(429, 120))
        w = World(self, providers=[provider])
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(result[(IP, BAD_IP)]['verdict'], score.LOOKUP_FAILED)
        w.engine.lookup([Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(len(provider.calls), 1, 'paused')
        w.clock.now += 121000
        w.engine.lookup([Indicator(IP, OTHER_IP)], external=True)
        self.assertEqual(len(provider.calls), 2)

    def test_refused_key_stops_quickly_and_does_not_retry(self):
        provider = Canned(answer=web_error(401))
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(w.store.provider_health()[0]['last_error'], 'key refused')

    def test_circuit_breaker_opens_and_closes(self):
        provider = Canned(answer=web_error(500))
        w = World(self, providers=[provider])
        for i in range(5):
            w.engine.lookup([Indicator(IP, f'8.8.{i}.1')], external=True)
        calls = len(provider.calls)
        w.engine.lookup([Indicator(IP, '8.8.9.1')], external=True)
        self.assertEqual(len(provider.calls), calls)
        w.clock.now += 901000
        provider.answer = clean
        w.engine.lookup([Indicator(IP, '8.8.9.1')], external=True)
        self.assertEqual(len(provider.calls), calls + 1)
        self.assertEqual(w.store.provider_health()[0]['consecutive'], 0)

    def test_malformed_response_is_a_failure_not_clean(self):
        provider = Canned(answer=p.BadResponse('not JSON'))
        w = World(self, providers=[provider])
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(result[(IP, BAD_IP)]['verdict'], score.LOOKUP_FAILED)
        self.assertEqual(len(provider.calls), 1)

    def test_only_kinds_a_provider_supports_are_sent(self):
        provider = Canned(answer=clean)
        provider.kinds = (IP,)
        w = World(self, providers=[provider])
        w.engine.lookup([Indicator(DOMAIN, 'example.com'), Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(provider.calls, [(IP, BAD_IP)])

    def test_unknown_to_a_known_files_list_is_not_clean(self):
        web = FakeWeb([Reply(b'', 404)])
        provider = p.CirclHashlookup()
        w = World(self, providers=[provider], web=web)
        result = w.engine.lookup([Indicator(HASH, BAD_HASH)], external=True)[(HASH, BAD_HASH)]
        self.assertEqual(result['verdict'], score.UNKNOWN)

    def test_unconfigured_provider_is_never_called(self):
        web = FakeWeb([Reply({})])
        w = World(self, providers=[p.AbuseIPDB(None)], web=web)
        w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(web.requests, [])


class UseCases(unittest.TestCase):
    """The ten required cases, with synthetic indicators."""

    def test_1_malicious_external_ip_in_network_telemetry(self):
        w = World(self)
        w.feed_file('c2', BAD_IP + '\n', confidence=95, quality=0.9)
        items = ind.extract({'destination': {'ip': BAD_IP}})
        self.assertEqual(w.engine.lookup(items)[(IP, BAD_IP)]['verdict'], score.MALICIOUS)

    def test_2_connection_to_a_known_malicious_domain(self):
        w = World(self)
        w.feed_file('d', BAD_DOMAIN + '\n', kind=DOMAIN, confidence=95, quality=0.9)
        items = ind.extract({'dns': {'question': {'name': BAD_DOMAIN}}})
        self.assertEqual(w.engine.lookup(items)[(DOMAIN, BAD_DOMAIN)]['verdict'], score.MALICIOUS)

    def test_3_file_hash_of_known_malware(self):
        w = World(self)
        w.feed_file('h', f'sha256,{BAD_HASH},TestFamily\n', format='indicators', kind=HASH, confidence=95, quality=0.9)
        result = w.engine.lookup(ind.extract({'process': {'hash': {'sha256': BAD_HASH}}}))[(HASH, BAD_HASH)]
        self.assertEqual(result['verdict'], score.MALICIOUS)
        self.assertEqual(result['sources'][0]['categories'], ['TestFamily'])

    def test_4_suspicious_url_in_alert_evidence(self):
        w = World(self)
        w.feed_file('u', BAD_URL + '\n', kind=URL, confidence=95, quality=0.9)
        items = ind.extract_alert({'evidence': {'matched_fields': {'process.command_line': [f'tool {BAD_URL}?session=abc']}}})
        result = w.engine.lookup(items)[(URL, BAD_URL)]
        self.assertEqual(result['verdict'], score.MALICIOUS)
        self.assertTrue(result['from_restricted_text'])
        self.assertNotIn('abc', json.dumps(result))

    def test_5_multiple_independent_sources(self):
        one, two = Canned('one', bad), Canned('two', bad)
        w = World(self, providers=[one, two])
        w.feed_file('f', BAD_IP + '\n', quality=0.6, confidence=70)
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)[(IP, BAD_IP)]
        self.assertEqual(result['independent_sources'], 3)
        self.assertEqual(result['verdict'], score.MALICIOUS)
        self.assertGreater(result['score'], 90)

    def test_6_conflicting_reputation(self):
        w = World(self, providers=[Canned('hostile', bad), Canned('friendly', good)])
        result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)[(IP, BAD_IP)]
        self.assertEqual(result['verdict'], score.CONFLICTING)
        self.assertTrue(any('hostile' in r for r in result['reasons']) and any('friendly' in r for r in result['reasons']))

    def test_7_unknown_indicator(self):
        result = World(self).engine.lookup([Indicator(DOMAIN, 'nothing-known.example.com')])[(DOMAIN, 'nothing-known.example.com')]
        self.assertEqual(result['verdict'], score.UNKNOWN)
        self.assertEqual(result['score'], 0)

    def test_8_provider_unavailable_or_rate_limited(self):
        for error in (web_error(503), web_error(429, 60), helpers.WebError('TimeoutError')):
            w = World(self, providers=[Canned(answer=error)])
            result = w.engine.lookup([Indicator(IP, BAD_IP)], external=True)[(IP, BAD_IP)]
            self.assertEqual(result['verdict'], score.LOOKUP_FAILED, error)
            self.assertNotEqual(result['verdict'], score.NO_KNOWN_THREAT)

    def test_9_repeated_lookup_served_from_cache(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        for _ in range(10):
            w.engine.lookup([Indicator(IP, BAD_IP)], external=True)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(w.store.cache_stats(NOW)['canned']['hits'], 9)

    def test_10_private_ip_excluded_from_external_lookups(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        items = [Indicator(IP, value) for value in ('10.0.0.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', 'fe80::1', '203.0.113.5')]
        results = w.engine.lookup(items, external=True)
        self.assertEqual(provider.calls, [])
        self.assertTrue(all(not r['external_checked'] for r in results.values()))

    def test_private_address_is_unknown_and_not_called_clean(self):
        w = World(self)
        w.feed_file('f', BAD_IP + chr(10))
        for item in (Indicator(IP, '10.1.2.3'), Indicator(IP, '127.0.0.1'), Indicator(DOMAIN, 'dc01.corp')):
            self.assertEqual(w.engine.lookup([item])[item.key]['verdict'], score.UNKNOWN, item)

    def test_restricted_text_is_never_sent_out(self):
        provider = Canned(answer=bad)
        w = World(self, providers=[provider])
        items = ind.extract({'process': {'command_line': 'curl https://secret-host.example.com/x 8.8.8.8'}})
        w.engine.lookup(items, external=True)
        self.assertEqual(provider.calls, [])


def alert(alert_id='a' * 32, fields=None, refs=('siem-windows-x/ev1',)):
    return {'alert_id': alert_id, 'rule_id': 'r1', 'rule_name': 'Test', 'severity': 'medium', 'evidence_ref': f'siem-alerts-x/{alert_id}', 'source_event_ids': [r.split('/')[1] for r in refs],
            'raw_event_refs': list(refs), 'evidence': {'matched_fields': fields or {'destination.ip': [BAD_IP]}}}


def stored(ident='ev1', ingested=NOW - HOUR // 2, **extra):
    return {'event': {'id': ident, 'ingested': ingested, 'code': '3'}, 'host': {'name': 'H'}, '@timestamp': '2026-10-31T10:00:00.000Z', **extra}


class Service(unittest.TestCase):
    def world(self, opensearch, providers=None):
        w = World(self, providers=providers)
        w.feed_file('c2', BAD_IP + '\n', confidence=95, quality=0.9)
        w.worker = service.Worker(w.store, w.engine, opensearch, clock=w.clock, external=True, log=lambda t: None)
        return w

    def test_alert_is_enriched_and_linked_by_its_id(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        w.worker.discover_alerts()
        self.assertEqual(w.worker.run_jobs(), 1)
        index, document = source.written['a' * 32]
        self.assertTrue(index.startswith('siem-enrichment-'))
        self.assertEqual(document['alert_id'], 'a' * 32)
        self.assertEqual(document['raw_event_refs'], ['siem-windows-x/ev1'])
        self.assertEqual(document['status'], 'complete')
        self.assertEqual(document['summary']['highest_verdict'], score.MALICIOUS)

    def test_the_alert_itself_is_never_changed(self):
        original = alert()
        before = json.dumps(original, sort_keys=True)
        source = FakeOpenSearch([original])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        self.assertEqual(json.dumps(original, sort_keys=True), before)
        self.assertEqual(list(source.written), ['a' * 32])

    def test_severity_is_recorded_and_not_altered(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        self.assertEqual(source.written['a' * 32][1]['alert_severity'], 'medium')
        self.assertNotIn('severity', source.written['a' * 32][1]['summary'])

    def test_repeat_sightings_make_one_job(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        self.assertEqual(w.worker.discover_alerts(), 1)
        self.assertEqual(w.worker.discover_alerts(), 0)
        w.worker.run_jobs()
        self.assertEqual(w.worker.run_jobs(), 0)

    def test_indicators_in_source_events_are_found(self):
        source = FakeOpenSearch([alert(fields={'user.name': ['bob']})], [stored(destination={'ip': BAD_IP})])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        self.assertEqual(source.written['a' * 32][1]['summary']['highest_verdict'], score.MALICIOUS)

    def test_alert_whose_events_have_expired_still_works(self):
        source = FakeOpenSearch([alert()], [])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        document = source.written['a' * 32][1]
        self.assertEqual(document['events_available'], 0)
        self.assertEqual(document['summary']['highest_verdict'], score.MALICIOUS)

    def test_alert_with_no_indicators_says_so(self):
        source = FakeOpenSearch([alert(fields={'user.name': ['bob']}, refs=())])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        self.assertEqual(source.written['a' * 32][1]['status'], 'no_indicators')

    def test_failed_lookup_is_visible_and_retried(self):
        provider = Canned(answer=web_error(503))
        source = FakeOpenSearch([alert(fields={'destination.ip': [OTHER_IP]}, refs=())])
        w = self.world(source, [provider])
        w.worker.discover_alerts()
        w.worker.run_jobs()
        document = source.written['a' * 32][1]
        self.assertEqual(document['status'], 'partial')
        self.assertFalse(document['indicators'][0]['complete'])
        self.assertEqual(w.store.job_counts(), {'partial': 1})
        self.assertEqual(w.worker.run_jobs(), 0, 'waits for its retry time')
        provider.answer = clean
        w.store.db.execute('UPDATE health SET open_until_ms = 0')
        w.clock.now += HOUR
        w.worker.run_jobs()
        self.assertEqual(source.written['a' * 32][1]['status'], 'complete')

    def test_retries_stop_at_the_limit(self):
        source = FakeOpenSearch([alert(fields={'destination.ip': [OTHER_IP]}, refs=())])
        w = self.world(source, [Canned(answer=web_error(503))])
        w.worker.discover_alerts()
        for _ in range(8):
            w.worker.run_jobs()
            w.clock.now += 10 * HOUR
            w.store.db.execute('UPDATE health SET open_until_ms = 0')
        self.assertEqual(w.store.job_attempts('a' * 32), 5)
        self.assertEqual(w.store.jobs_due(w.clock(), 10), [])

    def test_opensearch_outage_keeps_the_job(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        w.worker.discover_alerts()
        source.fail = 1
        self.assertEqual(w.worker.run_jobs(), 0)
        self.assertEqual(w.store.job_counts(), {'pending': 1})
        w.clock.now += HOUR
        self.assertEqual(w.worker.run_jobs(), 1)

    def test_alert_watermark_does_not_move_on_failure(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        w.worker.discover_alerts()
        mark = w.store.mark('alerts')
        w.clock.now += HOUR
        source.fail = 1
        with self.assertRaises(service.StoreError):
            w.worker.discover_alerts()
        self.assertEqual(w.store.mark('alerts'), mark)

    def test_events_are_matched_locally_with_no_external_call(self):
        provider = Canned(answer=bad)
        source = FakeOpenSearch([], [stored(destination={'ip': BAD_IP}), stored('ev2', destination={'ip': OTHER_IP})])
        w = self.world(source, [provider])
        result = w.worker.scan_events()
        self.assertEqual(provider.calls, [])
        self.assertEqual(result['events'], 2)
        self.assertEqual(result['matches'], 1)
        self.assertEqual(len(source.written), 1)
        document = next(iter(source.written.values()))[1]
        self.assertEqual(document['doc_type'], 'event')
        self.assertEqual(document['event_id'], 'ev1')

    def test_event_writes_are_repeatable(self):
        source = FakeOpenSearch([], [stored(destination={'ip': BAD_IP})])
        w = self.world(source)
        w.worker.scan_events()
        w.clock.now += MIN
        w.worker.scan_events()
        self.assertEqual(len(source.written), 1)

    def test_scan_only_stores_findings(self):
        source = FakeOpenSearch([], [stored(destination={'ip': OTHER_IP})])
        w = self.world(source)
        w.worker.scan_events()
        self.assertEqual(source.written, {})

    def test_backfill_dry_run_writes_nothing_and_moves_nothing(self):
        source = FakeOpenSearch([], [stored(destination={'ip': BAD_IP})])
        w = self.world(source)
        result = w.worker.scan_events(NOW - 2 * HOUR, NOW, write=False)
        self.assertEqual(result['matches'], 1)
        self.assertEqual(source.written, {})
        self.assertIsNone(w.store.mark('events'))

    def test_backfill_does_not_move_the_live_watermark(self):
        source = FakeOpenSearch([], [stored(destination={'ip': BAD_IP})])
        w = self.world(source)
        w.store.set_mark('events', NOW - 100)
        w.worker.scan_events(NOW - 2 * HOUR, NOW)
        self.assertEqual(w.store.mark('events'), NOW - 100)

    def test_backfill_cap_is_honoured(self):
        source = FakeOpenSearch([], [stored(f'ev{i}', destination={'ip': OTHER_IP}) for i in range(5)])
        w = self.world(source)
        w.worker.page = 2
        self.assertLessEqual(w.worker.scan_events(NOW - 2 * HOUR, NOW, write=False, max_events=2)['events'], 2 + 3)

    def test_health_flags_a_stale_feed(self):
        w = self.world(FakeOpenSearch())
        self.assertEqual(w.worker.health()['status'], 'OK')
        w.clock.now += 100 * HOUR
        self.assertEqual(w.worker.health()['status'], 'WARN')

    def test_health_flags_a_paused_provider(self):
        w = self.world(FakeOpenSearch(), [Canned(answer=web_error(429, 600))])
        w.engine.lookup([Indicator(IP, OTHER_IP)], external=True)
        self.assertIn('paused', w.worker.health()['message'])

    def test_ecs_shape(self):
        result = {'type': IP, 'value': BAD_IP, 'field': 'destination.ip', 'verdict': 'malicious', 'sources': [{'source': 'c2'}]}
        entry = service.ecs_entry(result, 'i', 'e')
        self.assertEqual(entry['indicator']['type'], 'ipv4-addr')
        self.assertEqual(entry['indicator']['ip'], BAD_IP)
        self.assertEqual(entry['matched'], {'atomic': BAD_IP, 'field': 'destination.ip', 'type': 'indicator_match_rule', 'index': 'i', 'id': 'e'})

    def test_stored_result_holds_no_raw_command_line(self):
        line = f'tool --flag {BAD_URL}?token=TOPSECRET'
        source = FakeOpenSearch([alert(fields={'process.command_line': [line]}, refs=())])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        text = json.dumps(source.written['a' * 32][1])
        self.assertNotIn('TOPSECRET', text)
        self.assertNotIn('--flag', text)

    def test_results_warn_that_intelligence_is_data(self):
        source = FakeOpenSearch([alert()])
        w = self.world(source)
        w.worker.discover_alerts()
        w.worker.run_jobs()
        self.assertIn('not instructions', source.written['a' * 32][1]['untrusted_notice'])


class Independence(unittest.TestCase):
    def test_the_detector_imports_nothing_from_the_enricher(self):
        for path in (helpers.ROOT / 'detector').rglob('*.py'):
            self.assertNotIn('siem_enricher', path.read_text(encoding='utf8'), path)

    def test_the_enricher_has_no_kafka_client(self):
        for path in (helpers.ROOT / 'enricher').rglob('*.py'):
            text = path.read_text(encoding='utf8')
            self.assertNotIn('confluent', text, path)
            self.assertNotIn('kafka', text.lower(), path)

    def test_only_one_module_opens_outside_connections(self):
        for path in (helpers.ROOT / 'enricher' / 'siem_enricher').glob('*.py'):
            if path.name not in ('web.py', 'service.py'):
                self.assertNotIn('urllib.request', path.read_text(encoding='utf8'), path)

    def test_no_dns_resolution_anywhere(self):
        for path in (helpers.ROOT / 'enricher').rglob('*.py'):
            text = path.read_text(encoding='utf8')
            for word in ('getaddrinfo', 'gethostbyname', 'dns.resolver'):
                self.assertNotIn(word, text, path)


if __name__ == '__main__':
    unittest.main()
