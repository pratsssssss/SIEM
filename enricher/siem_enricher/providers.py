"""External providers behind one interface. A provider turns a response into an Observation, and any
malformed answer raises BadResponse, which is recorded as a failure and never as clean."""
import json
import urllib.parse

from . import indicators as ind
from . import score, untrusted
from .score import HIT, NO_MATCH, SKIPPED, Observation


class BadResponse(Exception):
    pass


class Provider:
    name = ''
    publisher = ''
    host = ''
    kinds = ()
    needs_key = True
    quality = 0.5
    per_minute = 4
    per_day = 500

    def __init__(self, key=None):
        self.key = key

    def configured(self):
        return bool(self.key) or not self.needs_key

    def _observe(self, status=NO_MATCH, **values):
        return Observation(source=self.name, publisher=self.publisher, status=status, quality=self.quality, **values)

    def query(self, web, kind, value):
        raise NotImplementedError


def _json(body):
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise BadResponse('not JSON') from error
    if not isinstance(data, dict):
        raise BadResponse('not an object')
    return data


class AbuseIPDB(Provider):
    name, publisher, host = 'abuseipdb', 'abuseipdb', 'api.abuseipdb.com'
    kinds = (ind.IP,)
    quality = 0.8
    per_minute, per_day = 30, 1000

    def query(self, web, kind, value):
        url = 'https://api.abuseipdb.com/api/v2/check?' + urllib.parse.urlencode({'ipAddress': value, 'maxAgeInDays': 90})
        _, _, body = web.fetch(url, {'Key': self.key, 'Accept': 'application/json'})
        data = _json(body).get('data')
        if not isinstance(data, dict):
            raise BadResponse('no data object')
        confidence = untrusted.number(data.get('abuseConfidenceScore'), 0, 100)
        reports = untrusted.number(data.get('totalReports'), 0)
        if confidence is None or reports is None:
            raise BadResponse('score or reports out of range')
        detail = {'reports': reports, 'distinct_users': untrusted.number(data.get('numDistinctUsers'), 0), 'usage': untrusted.label(data.get('usageType')), 'isp': untrusted.label(data.get('isp')), 'country': untrusted.label(data.get('countryCode'))}
        detail = {k: v for k, v in detail.items() if v is not None}
        last = untrusted.timestamp(data.get('lastReportedAt'))
        if reports == 0 or confidence == 0:
            return self._observe(detail=detail, last_seen=last)
        stance = 'malicious' if confidence >= 75 else 'suspicious'
        return self._observe(HIT, stance=stance, confidence=confidence, categories=['abuse-reports'], last_seen=last, detail=detail)


class VirusTotal(Provider):
    name, publisher, host = 'virustotal', 'virustotal', 'www.virustotal.com'
    kinds = (ind.IP, ind.DOMAIN, ind.HASH, ind.URL)
    quality = 0.85
    per_minute, per_day = 4, 500

    def query(self, web, kind, value):
        path = {ind.IP: 'ip_addresses', ind.DOMAIN: 'domains', ind.HASH: 'files'}.get(kind)
        if kind == ind.URL:
            import base64
            target = 'urls/' + base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
        else:
            target = f'{path}/{urllib.parse.quote(value, safe="")}'
        status, _, body = web.fetch(f'https://www.virustotal.com/api/v3/{target}', {'x-apikey': self.key, 'Accept': 'application/json'})
        if status == 404:
            return self._observe()
        attributes = (_json(body).get('data') or {}).get('attributes') if isinstance(_json(body).get('data'), dict) else None
        if not isinstance(attributes, dict):
            raise BadResponse('no attributes')
        stats = attributes.get('last_analysis_stats')
        if not isinstance(stats, dict):
            raise BadResponse('no analysis stats')
        malicious = untrusted.number(stats.get('malicious'), 0, 1000)
        suspicious = untrusted.number(stats.get('suspicious'), 0, 1000)
        harmless = untrusted.number(stats.get('harmless', 0), 0, 1000)
        undetected = untrusted.number(stats.get('undetected', 0), 0, 1000)
        if None in (malicious, suspicious, harmless, undetected):
            raise BadResponse('counts out of range')
        total = malicious + suspicious + harmless + undetected
        detail = {'engines_malicious': malicious, 'engines_suspicious': suspicious, 'engines_total': total}
        first = untrusted.timestamp(attributes.get('first_submission_date') or attributes.get('creation_date'))
        last = untrusted.timestamp(attributes.get('last_analysis_date'))
        if kind == ind.DOMAIN:
            created = untrusted.timestamp(attributes.get('creation_date'))
            registrar = untrusted.label(attributes.get('registrar'))
            detail.update({k: v for k, v in (('domain_created', created), ('registrar', registrar)) if v})
        names = untrusted.labels([(attributes.get('popular_threat_classification') or {}).get('suggested_threat_label')]) if isinstance(attributes.get('popular_threat_classification'), dict) else []
        if malicious >= 5:
            return self._observe(HIT, stance='malicious', confidence=min(50 + malicious * 5, 100), categories=names, first_seen=first, last_seen=last, detail=detail)
        if malicious or suspicious:
            return self._observe(HIT, stance='suspicious', confidence=min(30 + (malicious + suspicious) * 10, 80), categories=names, first_seen=first, last_seen=last, detail=detail)
        return self._observe(first_seen=first, last_seen=last, detail=detail)


class OTX(Provider):
    name, publisher, host = 'otx', 'otx', 'otx.alienvault.com'
    kinds = (ind.IP, ind.DOMAIN, ind.HASH, ind.URL)
    quality = 0.5
    per_minute, per_day = 60, 5000

    def query(self, web, kind, value):
        section = {ind.IP: 'IPv6' if ':' in value else 'IPv4', ind.DOMAIN: 'domain', ind.HASH: 'file', ind.URL: 'url'}[kind]
        url = f'https://otx.alienvault.com/api/v1/indicators/{section}/{urllib.parse.quote(value, safe="")}/general'
        status, _, body = web.fetch(url, {'X-OTX-API-KEY': self.key, 'Accept': 'application/json'})
        if status == 404:
            return self._observe()
        data = _json(body)
        info = data.get('pulse_info')
        if not isinstance(info, dict):
            raise BadResponse('no pulse_info')
        count = untrusted.number(info.get('count'), 0)
        if count is None:
            raise BadResponse('count out of range')
        if isinstance(data.get('validation'), list) and any(isinstance(v, dict) and v.get('source') in ('whitelist', 'majestic', 'alexa', 'akamai') for v in data['validation']):
            return self._observe(HIT, stance='benign', confidence=70, categories=['allowlisted'], detail={'pulses': count})
        if count == 0:
            return self._observe()
        return self._observe(HIT, stance='suspicious' if count < 3 else 'malicious', confidence=min(40 + count * 10, 90), categories=['community-pulse'], detail={'pulses': count})


class AbuseCh(Provider):
    """URLhaus and MalwareBazaar lookups. Both need a free Auth-Key since their bulk feeds closed."""
    name, publisher, host = 'abusech', 'abuse.ch', 'urlhaus-api.abuse.ch'
    kinds = (ind.URL, ind.DOMAIN, ind.HASH, ind.IP)
    quality = 0.9
    per_minute, per_day = 30, 2000

    def query(self, web, kind, value):
        if kind == ind.HASH:
            url = 'https://mb-api.abuse.ch/api/v1/'
            form = {'query': 'get_info', 'hash': value}
        else:
            url = f"https://urlhaus-api.abuse.ch/v1/{'url' if kind == ind.URL else 'host'}/"
            form = {'url': value} if kind == ind.URL else {'host': value}
        _, _, body = web.fetch(url, {'Auth-Key': self.key, 'Accept': 'application/json'}, urllib.parse.urlencode(form).encode())
        data = _json(body)
        state = data.get('query_status')
        if state in ('no_results', 'hash_not_found', 'illegal_hash'):
            return self._observe()
        if state != 'ok':
            raise BadResponse('unexpected query_status')
        if kind == ind.HASH:
            rows = data.get('data')
            if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
                raise BadResponse('no data')
            row = rows[0]
            return self._observe(HIT, stance='malicious', confidence=95, categories=untrusted.labels([row.get('signature'), *(row.get('tags') or [])]), first_seen=untrusted.timestamp(row.get('first_seen')), last_seen=untrusted.timestamp(row.get('last_seen')))
        online = data.get('url_status') == 'online' or (data.get('url_count') not in (None, 0, '0'))
        return self._observe(HIT, stance='malicious', confidence=90 if online else 70, categories=untrusted.labels(['malware-distribution', data.get('threat')]), first_seen=untrusted.timestamp(data.get('firstseen') or data.get('date_added')), last_seen=untrusted.timestamp(data.get('lastseen') or data.get('last_online')))


class CirclHashlookup(Provider):
    """Known files, mostly from NSRL. A hit means known and usually benign. No key is needed, but
    sending a hash still tells a third party that this file exists here, so it is off by default."""
    name, publisher, host = 'circl-hashlookup', 'circl', 'hashlookup.circl.lu'
    kinds = (ind.HASH,)
    needs_key = False
    quality = 0.6
    per_minute, per_day = 60, 5000

    def query(self, web, kind, value):
        status, _, body = web.fetch(f'https://hashlookup.circl.lu/lookup/sha256/{value}', {'Accept': 'application/json'})
        if status == 404:
            # It lists known files, not threats, so not being listed says nothing about a file.
            return self._observe(SKIPPED, detail={'reason': 'not in a list of known files'})
        data = _json(body)
        if str(data.get('SHA-256', '')).lower() != value:
            raise BadResponse('answer is for a different hash')
        trust = untrusted.number(data.get('hashlookup:trust'), 0, 100)
        if trust is None:
            trust = 50
        return self._observe(HIT, stance='benign', confidence=trust, categories=['known-file'], detail={'known_file': True})


ALL = {cls.name: cls for cls in (AbuseIPDB, VirusTotal, OTX, AbuseCh, CirclHashlookup)}
__all__ = ['ALL', 'BadResponse', 'Provider', 'score']
