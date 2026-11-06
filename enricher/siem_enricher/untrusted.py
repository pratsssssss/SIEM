"""Threat intelligence is untrusted input. Nothing a provider says reaches storage unfiltered.

Free text is never kept, because a later automated stage could read it as instructions. A provider can only
contribute numbers, dates, and short labels drawn from a closed alphabet. See docs/detection/threat-intelligence.md.
"""
import re
from datetime import datetime, timezone

MAX_LABELS = 12
_LABEL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._:/+#-]{0,47}$')
# Words that have no place in a malware or category label, and suggest an attempt at instructions.
_SUSPECT = re.compile(r'ignore|instruction|prompt|system|assistant|disregard|http|www\.', re.IGNORECASE)


def label(value):
    """A short name, such as a malware family, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _LABEL.match(text) or _SUSPECT.search(text):
        return None
    return text


def labels(values):
    """Accepted labels, in order, without repeats, capped."""
    if not isinstance(values, (list, tuple)):
        values = [values]
    found = []
    for value in values:
        item = label(value)
        if item and item.lower() not in {f.lower() for f in found}:
            found.append(item)
        if len(found) == MAX_LABELS:
            break
    return found


def number(value, low=0, high=None):
    """An in-range integer, or None. A boolean is not a number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float('inf'), float('-inf')):
        return None
    result = int(value)
    if result < low or (high is not None and result > high):
        return None
    return result


def timestamp(value):
    """An ISO 8601 UTC string, or None. Accepts epoch seconds and common date formats. Rejects the future."""
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            moment = datetime.fromisoformat(value.strip().replace(' UTC', '+00:00').replace('Z', '+00:00').replace(' ', 'T', 1))
            moment = moment.replace(tzinfo=moment.tzinfo or timezone.utc).astimezone(timezone.utc)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    if moment > datetime.now(timezone.utc) or moment.year < 2000:
        return None
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')
