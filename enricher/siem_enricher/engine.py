"""Looks up indicators: local data always, external providers only when asked and only when allowed.

Provider calls go through one path that applies the cache, circuit breaker, rate limits and retries.
A failure comes back as an Observation with an error status, and so is never mistaken for clean.
"""
import json
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import feeds as feed_lib
from . import indicators as ind
from . import score
from .providers import BadResponse
from .score import ERROR, HIT, NO_MATCH, RATE_LIMITED, Observation
from .web import WebError

DAY = 86400
DEFAULT_TTL = {
    'hit': {ind.IP: DAY, ind.DOMAIN: 3 * DAY, ind.URL: DAY, ind.HASH: 30 * DAY},
    'clean': {ind.IP: 6 * 3600, ind.DOMAIN: DAY, ind.URL: 6 * 3600, ind.HASH: 7 * DAY},
}


@dataclass
class Limits:
    workers: int = 4
    retries: int = 3
    backoff_seconds: float = 2.0
    max_backoff_seconds: float = 30.0
    breaker_failures: int = 5
    breaker_seconds: int = 900
    allow_external_urls: bool = False
    ttl: dict = field(default_factory=lambda: DEFAULT_TTL)


def _encode(observation):
    return dict(observation.__dict__)


def _decode(body):
    return Observation(**body)


class Engine:
    def __init__(self, store, feeds, geo, providers, web, limits=None, clock=None, sleep=time.sleep, log=print):
        self.store = store
        self.feeds = feeds
        self.geo = geo
        self.providers = providers
        self.web = web
        self.limits = limits or Limits()
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.sleep = sleep
        self.log = log
        self.minute = {name: deque() for name in providers}
        self.guard = threading.Lock()
        self.flying = {}

    def _ttl(self, observation, kind):
        return self.limits.ttl['hit' if observation.status == HIT else 'clean'][kind]

    def _minute_slot(self, provider):
        now = self.clock()
        with self.guard:
            window = self.minute[provider.name]
            while window and now - window[0] >= 60000:
                window.popleft()
            if len(window) >= provider.per_minute:
                return False
            window.append(now)
            return True

    def _failed(self, provider, status, reason):
        return Observation(source=provider.name, publisher=provider.publisher, status=status, detail={'reason': reason})

    def _call(self, provider, kind, value):
        """One provider, one indicator, through every safeguard."""
        now = self.clock()
        held = self.store.cached(provider.name, kind, value, now)
        if held is not None:
            self.store.bump('cache_hit')
            return _decode(held)
        self.store.bump('cache_miss')
        if self.store.provider_open_until(provider.name) > now:
            return self._failed(provider, ERROR, 'provider paused after failures')
        if not self._minute_slot(provider):
            return self._failed(provider, RATE_LIMITED, 'local per-minute limit')
        day = datetime.fromtimestamp(now / 1000, timezone.utc).strftime('%Y-%m-%d')
        if not self.store.quota_take(provider.name, day, provider.per_day):
            return self._failed(provider, RATE_LIMITED, 'local daily limit')
        reason = 'unknown failure'
        for attempt in range(self.limits.retries):
            if attempt:
                self.sleep(min(self.limits.backoff_seconds * 2 ** (attempt - 1), self.limits.max_backoff_seconds))
            try:
                observation = provider.query(self.web, kind, value)
            except WebError as error:
                reason = str(error)
                if error.status == 429:
                    wait = min(error.retry_after or 60, 3600)
                    self.store.health_failed(provider.name, reason, self.clock(), 1, wait * 1000)
                    return self._failed(provider, RATE_LIMITED, 'provider rate limit')
                if error.status in (401, 403):
                    self.store.health_failed(provider.name, 'key refused', self.clock(), 1, 3600000)
                    return self._failed(provider, ERROR, 'key refused')
                if error.status is not None and error.status < 500:
                    break
                continue
            except BadResponse as error:
                reason = f'invalid response: {error}'
                break
            self.store.health_ok(provider.name, self.clock())
            self.store.cache_put(provider.name, kind, value, _encode(observation), self.clock(), self._ttl(observation, kind))
            return observation
        self.store.health_failed(provider.name, reason, self.clock(), self.limits.breaker_failures, self.limits.breaker_seconds * 1000)
        return self._failed(provider, ERROR, reason)

    def _once(self, pool, provider, kind, value):
        """A request already running is shared, so two callers make one call."""
        key = (provider.name, kind, value)
        with self.guard:
            future = self.flying.get(key)
            if future is None:
                future = pool.submit(self._call, provider, kind, value)
                self.flying[key] = future
                future.add_done_callback(lambda _: self._forget(key))
        return future

    def _forget(self, key):
        with self.guard:
            self.flying.pop(key, None)

    def local(self, indicator):
        return [*self.feeds.lookup(indicator.kind, indicator.value), *feed_lib.heuristics(indicator.kind, indicator.value)]

    def context(self, indicator):
        if indicator.kind != ind.IP:
            return {}
        found = dict(self.geo.lookup(indicator.value)) if self.geo else {}
        tags = [o.source for o in self.feeds.lookup(ind.IP, indicator.value) if o.status == HIT and not o.reputation]
        if tags:
            found['network_tags'] = tags
        return found

    @staticmethod
    def _reputable(item):
        if item.kind == ind.IP:
            return ind.is_public_ip(item.value)
        if item.kind == ind.DOMAIN:
            return ind.is_public_domain(item.value)
        return True

    def lookup(self, items, external=False):
        """Results keyed by (kind, value). Repeats in `items` make one lookup."""
        unique = ind.merge(items)
        local = {item.key: self.local(item) for item in unique}
        remote = {item.key: [] for item in unique}
        checked = set()
        if external and self.providers:
            with ThreadPoolExecutor(max_workers=self.limits.workers, thread_name_prefix='lookup') as pool:
                for item in unique:
                    if not ind.external_allowed(item, self.limits.allow_external_urls):
                        continue
                    for provider in self.providers.values():
                        if item.kind in provider.kinds and provider.configured():
                            remote[item.key].append(self._once(pool, provider, item.kind, item.value))
                            checked.add(item.key)
            remote = {key: [f.result() for f in futures] for key, futures in remote.items()}
        results = {}
        for item in unique:
            observations = [*local[item.key], *remote[item.key]]
            if not self._reputable(item):
                # Public lists say nothing about private space, so their silence is not an answer.
                observations = [o for o in observations if o.status != NO_MATCH]
            verdict = score.evaluate(item.kind, observations, datetime.fromtimestamp(self.clock() / 1000, timezone.utc))
            results[item.key] = {
                'type': item.kind, 'value': item.value, 'field': item.field, 'from_restricted_text': item.restricted,
                'external_checked': item.key in checked, **verdict, 'context': self.context(item),
                'sources': [o.public() for o in observations if o.status != 'no_match'],
            }
        self.store.bump('lookups', len(unique))
        return results


def serialize(results):
    return json.dumps(results, sort_keys=True)
