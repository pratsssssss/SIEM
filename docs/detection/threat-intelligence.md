# Threat Intelligence Sources

**Status:** checked on 2026-10-31. Terms change, so read each source's own terms before relying on them, and always before any use outside this lab. **Verified** means this project requested it that day. **Reported** means a third party says so, and it was not confirmed.

## Summary

| Indicator | With no account or key | With a free key |
|---|---|---|
| IP | Malicious, suspicious, Tor, cloud, country, region, ASN | Abuse reports, scores, vendor counts |
| Domain | Phishing lists, name signals, seen resolutions | Age, registrar, vendor counts |
| URL | Phishing list, and listed host | Vendor counts, if the owner allows URLs out |
| SHA-256 | **No reputation source exists.** The verdict is `unknown` | Malware names, vendor counts, first and last seen |

**Hashes are the real gap.** The free bulk malware hash feeds have closed. Without a key, a hash can only be matched against a file the owner supplies, in `data/enrichment/owner/`.

## Local feeds

All need no key or account. They are downloaded by a timer, and held in SQLite. Only a request for the list leaves the host: no indicator from this SIEM is sent. The publisher does see this host's public IP address.

| Feed | Covers | Rows on 2026-10-31 | Freshness | Limits |
|---|---|---:|---|---|
| Spamhaus DROP | Hijacked IPv4 netblocks | 1,757 | Dated the same week | Whole netblocks. Check Spamhaus's terms for your use |
| Feodo Tracker | Botnet C2 IPs | 5 | **Last updated March 2026, so nearly dormant** | Stale is allowed for this feed, because it is small and curated |
| ET Compromised | Compromised hosts | 542 | Daily | Small |
| CINS Army | Scanners and attackers | 15,000 | Daily | Marked suspicious, because a scanner is not a C2 |
| blocklist.de | Abuse reports | 25,732 | Daily | Marked suspicious. Shared hosting produces false positives |
| OpenPhish community | Phishing URLs | 300 | Hours | Only 300 URLs. Exact match. Moved to GitHub, so it is fetched there |
| Phishing Army | Phishing domains | 152,844 | Daily | Its header states that commercial users are responsible for upstream terms |
| Tor exit list | Tor exits | 1,224 | Daily | Context only, and never affects a verdict |
| AWS, Google Cloud ranges | Cloud networks | 11,449 and 1,151 | Weekly | Context only. A cloud address is not bad. No equally stable Azure URL was verified |
| DB-IP Lite | Country, region, ASN | Monthly file | Monthly | Reduced accuracy against the commercial data. **CC BY 4.0, so credit is required: "IP Geolocation by DB-IP"** |

### Considered and not used

| Source | Why not |
|---|---|
| URLhaus, MalwareBazaar and ThreatFox bulk feeds | **Verified:** return `410 Gone`. The APIs return 401 without a key |
| Hagezi Threat Intelligence Feeds | Works, but it is 1.86 million domains and 33 MB. It can be added, at about 15 times the database size |
| IPsum, FireHOL | These aggregate other lists, so using them would count one report twice and fake independence |
| MaxMind GeoLite2 | Needs an account and a license key, and accounts are out of scope |
| Active DNS, WHOIS or RDAP | Each query would expose what is being investigated |

## External providers

All are off without configuration. They run at alert time only (D8), and only for structured fields. Only `circl-hashlookup` needs no key, so it is off unless enabled.

| Provider | Covers | Access | Limits | Reliability |
|---|---|---|---|---|
| AbuseIPDB | IP | Free key, account needed | **Reported:** 1,000 checks a day. Set here at 30 a minute, 1,000 a day | Crowd reports. Strong for scanners and brute force |
| VirusTotal | IP, domain, hash, URL | Free key, account needed | **Official docs:** 500 a day, 4 a minute. Not for commercial products | Strong, but aggregated. Vendor counts vary |
| AlienVault OTX | IP, domain, hash, URL | Free key, account needed | **Reported:** older figures of 10,000 an hour. Not documented clearly. Set here at 60 a minute | Community pulses, with varying quality |
| abuse.ch API | URL, domain, IP, hash | Free Auth-Key, account needed. **Verified:** 401 without one | **Reported:** a few hundred a minute | High quality for malware |
| CIRCL hashlookup | Hash | No key. **Verified:** answers | Set here at 60 a minute | Mostly NSRL, so a hit means a known file, usually benign. It does not list malware |

Adapters for the keyed providers are **tested against mocked responses only**, because no keys exist here. CIRCL was also called live: see the acceptance report.

### Adding a provider key

```text
sudo install -m 640 -o root -g siem-enricher /dev/stdin /home/linux/siem/config/enricher/provider-keys.json
{"abuseipdb": "<key>", "virustotal": "<key>"}
<Ctrl-D>
sudo systemctl restart siem-enricher
sudo -u siem-enricher siem-enricher providers
```

Or set `SIEM_KEY_ABUSEIPDB` and similar in the service's environment. Never pass a key on a command line. Provider names are `abuseipdb`, `virustotal`, `otx`, `abusech`, and `circl-hashlookup`, which needs no key.

### Writing an adapter

Subclass `Provider` in `providers.py`: set `name`, `publisher`, `host`, `kinds`, `quality`, `per_minute` and `per_day`, and write `query(web, kind, value)`, which returns an `Observation`, or raises `BadResponse`. The cache, limits, retries and circuit breaker apply by themselves. Put every value through `untrusted.py`.

## Privacy

| What leaves | To whom | When | What they learn |
|---|---|---|---|
| List requests | Each feed's host | Timer | This host's public IP, and that it uses the list |
| Public IP | AbuseIPDB, VirusTotal, OTX, abuse.ch | Alert time, if keyed | Your account looked at that address |
| Public domain | VirusTotal, OTX, abuse.ch | Alert time, if keyed | Your account looked at that name. **VirusTotal lookups can be visible to its customers** |
| SHA-256 | VirusTotal, OTX, abuse.ch, CIRCL if enabled | Alert time, if configured | That a file with this hash exists here. A hash of a private document can identify it |
| URL | Same | **Off by default.** Only with `allow_external_urls`, and with query, credentials and fragment removed | The site and path. A path can still hold private text |

**Never sent:** event records, command lines, scripts, anything extracted from them, private or reserved addresses, internal names, or files. Nothing is sent for ordinary events, only for alerts. A URL is never fetched or opened, and no DNS query is made for an indicator.

## Scoring

Every result lists its sources and reasons. The same input always gives the same result.

**Strength of one answer** = `quality × confidence ÷ 100 × recency`, halved for a suspicious stance. Recency halves every 30 days for IPs and URLs and 90 for domains, with a floor of 0.25. Hashes do not fade.

**Combining:** the strongest answer per publisher is kept, then `score = 100 × (1 − ∏(1 − strength))`. Answers are never averaged, because a clean reply from a source with no data would dilute a real finding. Two feeds from one publisher count once.

| Verdict | Rule |
|---|---|
| `conflicting` | A hostile answer and a benign one, each of strength 0.4 or more |
| `malicious` | Score 70 or more, or 50 or more with two independent publishers calling it malicious |
| `suspicious` | Score 20 or more |
| `lookup_failed` | Every source that was asked failed |
| `unknown` | No source covers it, the signals are too weak, some sources failed, or it is a private address |
| `no_known_threat` | At least one real source answered, and none failed. **This is not proof of safety** |

A single listing is usually `suspicious`, on purpose: OpenPhish alone scores 68, and it takes a second source to reach `malicious`. Spamhaus and Feodo reach it alone, because they are curated. Geography, cloud and Tor tags never change a verdict.

Enrichment never changes an alert's severity, and never closes one.

## Untrusted data

A provider could be wrong or compromised, and later stages read these results. So no free text is stored. A provider contributes only numbers in range, valid past dates, and labels from a closed alphabet of 48 characters or fewer, with instruction-like words rejected. A malformed answer is a failure, never a clean result.

## Synthetic intelligence (D12)

A file named `synthetic-*.csv` in `data/enrichment/owner/` is test data, and appears under that name in every result. It exists only during a test, and is removed with `feeds purge`.

_Internal test reports and planning records mentioned here are not published with Version 1._
