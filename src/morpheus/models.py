"""Core dataclasses and enums shared across Morpheus.

Everything here is designed to be JSON-serializable via ``to_serializable`` so
scorecards and reports can be written with the stdlib only.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

_RANKS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


class Severity(str, Enum):
    """Severity levels ordered by :attr:`rank`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANKS[self.value]

    @property
    def weight(self) -> int:
        return _WEIGHTS[self.value]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls(str(value).strip().lower())


def to_serializable(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/containers to JSON-able values."""
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_serializable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_serializable(v) for v in obj]
    return obj


class _AsDictMixin:
    def as_dict(self) -> dict:
        return to_serializable(self)


@dataclass
class ToolCall(_AsDictMixin):
    name: str
    arguments: dict = field(default_factory=dict)
    raw: str = ""


@dataclass
class AgentRequest(_AsDictMixin):
    prompt: str
    system: Optional[str] = None
    context_documents: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    conversation_id: Optional[str] = None


@dataclass
class AgentResponse(_AsDictMixin):
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class Finding(_AsDictMixin):
    scenario_id: str
    category: str
    title: str
    passed: bool
    severity: Severity
    detector_name: str
    detector_detail: str
    atlas: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    remediation: str = ""
    request_prompt: str = ""
    response_excerpt: str = ""
    latency_ms: Optional[float] = None
    errored: bool = False
