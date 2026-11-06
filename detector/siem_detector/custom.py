"""Interface for custom Python rules. A rule sees events and returns findings, and nothing else:
it does not query, keep state, or publish. See docs/detection/writing-rules.md.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Finding:
    """One detection. `key` must be stable across runs: it is what makes a repeat a duplicate."""
    key: str
    events: list
    facts: dict = field(default_factory=dict)
    severity: str | None = None


class CustomRule(ABC):
    id: str
    title: str
    description: str
    level: str
    tags: tuple = ()
    # Candidate events are fetched for this long before the watermark, so a pattern can span runs.
    lookback_seconds: int = 900
    # Fields that must be returned with each event, beyond the standard context.
    fields: tuple = ()

    @abstractmethod
    def query(self) -> dict:
        """A Query DSL filter for candidate events. The time range is added by the runner."""

    @abstractmethod
    def detect(self, events: list) -> list:
        """Takes hits sorted by @timestamp. Returns Findings. Must be deterministic."""


def source(hit):
    return hit['_source']
