"""Deterministic scoring. Same observations, same result, with every reason listed.

Observations are never averaged, because a clean answer from a source with no data would dilute a
real finding. Strengths combine as independent evidence, one per publisher, so two feeds from one
organisation count once. See docs/detection/threat-intelligence.md for the worked rules.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

MALICIOUS, SUSPICIOUS, UNKNOWN, NO_KNOWN_THREAT, CONFLICTING, LOOKUP_FAILED = 'malicious', 'suspicious', 'unknown', 'no_known_threat', 'conflicting', 'lookup_failed'
VERDICT_ORDER = (MALICIOUS, CONFLICTING, SUSPICIOUS, LOOKUP_FAILED, UNKNOWN, NO_KNOWN_THREAT)

# Status of a source's answer. Only hit and no_match mean the source really answered.
HIT, NO_MATCH, ERROR, RATE_LIMITED, SKIPPED = 'hit', 'no_match', 'error', 'rate_limited', 'skipped'

HALF_LIFE_DAYS = {'ip': 30, 'domain': 90, 'url': 30, 'sha256': None}
MIN_RECENCY = 0.25
SUSPICIOUS_FACTOR = 0.5
MALICIOUS_SCORE = 70
CORROBORATED_SCORE = 50
SUSPICIOUS_SCORE = 20
CONFLICT_STRENGTH = 0.4


@dataclass
class Observation:
    """One source's answer about one indicator."""
    source: str
    publisher: str
    status: str
    stance: str = 'none'  # malicious, suspicious, benign, context, none
    quality: float = 0.0
    confidence: int = 0
    categories: list = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    detail: dict = field(default_factory=dict)
    reputation: bool = True  # False for geography and similar context

    def public(self):
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {}) and k != 'reputation'}


def recency(observation, kind, now):
    half_life = HALF_LIFE_DAYS.get(kind)
    if half_life is None or not observation.last_seen:
        return 1.0
    try:
        seen = datetime.fromisoformat(observation.last_seen.replace('Z', '+00:00'))
    except ValueError:
        return MIN_RECENCY
    age = max((now - seen).total_seconds() / 86400, 0)
    return max(0.5 ** (age / half_life), MIN_RECENCY)


def strength(observation, kind, now):
    factor = SUSPICIOUS_FACTOR if observation.stance == 'suspicious' else 1.0
    return min(observation.quality * observation.confidence / 100 * recency(observation, kind, now) * factor, 0.99)


def evaluate(kind, observations, now=None):
    """Returns the verdict, its score and the reasons. A missing answer is never treated as clean."""
    now = now or datetime.now(timezone.utc)
    reputation = [o for o in observations if o.reputation]
    answered = [o for o in reputation if o.status in (HIT, NO_MATCH)]
    failed = [o for o in reputation if o.status in (ERROR, RATE_LIMITED)]
    hostile = [o for o in reputation if o.status == HIT and o.stance in ('malicious', 'suspicious')]
    benign = [o for o in reputation if o.status == HIT and o.stance == 'benign']

    best = {}
    for item in hostile:
        value = strength(item, kind, now)
        if value > best.get(item.publisher, (0, None))[0]:
            best[item.publisher] = (value, item)
    remaining = 1.0
    for value, _ in best.values():
        remaining *= 1 - value
    score = round(100 * (1 - remaining))
    malicious_publishers = {o.publisher for o in hostile if o.stance == 'malicious'}
    top = max((v for v, _ in best.values()), default=0)
    clean = max((o.quality * o.confidence / 100 for o in benign), default=0)

    reasons = [f'{item.source}: {item.stance}, strength {value:.2f}' for value, item in sorted(best.values(), key=lambda p: (-p[0], p[1].source))]
    reasons += [f'{o.source}: benign, strength {o.quality * o.confidence / 100:.2f}' for o in benign]
    reasons += [f'{o.source}: {o.status}' for o in failed]

    if top >= CONFLICT_STRENGTH and clean >= CONFLICT_STRENGTH:
        verdict = CONFLICTING
    elif score >= MALICIOUS_SCORE or (len(malicious_publishers) >= 2 and score >= CORROBORATED_SCORE):
        verdict = MALICIOUS
    elif score >= SUSPICIOUS_SCORE:
        verdict = SUSPICIOUS
    elif failed and not answered:
        verdict = LOOKUP_FAILED
    elif hostile:
        verdict = UNKNOWN
        reasons.append('only weak signals, below the suspicious threshold')
    elif failed:
        verdict = UNKNOWN
        reasons.append('some sources failed, so silence from the others proves little')
    elif answered:
        verdict = NO_KNOWN_THREAT
        reasons.append(f'{len(answered)} sources hold nothing against it. This is not proof that it is safe')
    else:
        verdict = UNKNOWN
        reasons.append('no source covers this indicator')
    return {
        'verdict': verdict, 'score': score, 'independent_sources': len(best), 'complete': not failed,
        'sources_answered': sorted(o.source for o in answered), 'sources_failed': sorted(o.source for o in failed), 'reasons': reasons,
    }


def worst(verdicts):
    """The verdict that most needs attention, for a summary."""
    return min(verdicts, key=VERDICT_ORDER.index) if verdicts else UNKNOWN
