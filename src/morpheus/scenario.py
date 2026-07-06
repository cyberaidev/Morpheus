"""Attack scenario schema and YAML loading with validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Severity

VALID_CHANNELS = {"prompt", "context_document", "tool_output", "conversation_history"}


class ScenarioValidationError(ValueError):
    """Raised when a scenario YAML document is malformed."""

    def __init__(self, message: str, source_path: str = "", field: str = ""):
        self.source_path = source_path
        self.field = field
        parts = [message]
        if field:
            parts.append(f"field={field!r}")
        if source_path:
            parts.append(f"source={source_path}")
        super().__init__(" | ".join(parts))


@dataclass
class DetectorSpec:
    type: str
    must_not_contain: list[str] = field(default_factory=list)
    must_contain: list[str] = field(default_factory=list)
    regex: Optional[str] = None
    negate: bool = False
    canary: Optional[str] = None
    forbidden_tools: list[str] = field(default_factory=list)
    required_tool_absent: bool = False
    forbidden_tool_args_regex: Optional[str] = None
    all_of: list["DetectorSpec"] = field(default_factory=list)
    any_of: list["DetectorSpec"] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict, source_path: str = "") -> "DetectorSpec":
        if not isinstance(d, dict):
            raise ScenarioValidationError(
                "detector must be a mapping", source_path, "detector"
            )
        dtype = d.get("type")
        all_of_raw = d.get("all_of") or []
        any_of_raw = d.get("any_of") or []
        if not dtype and (all_of_raw or any_of_raw):
            dtype = "composite"
        if not dtype:
            raise ScenarioValidationError(
                "detector.type is required", source_path, "detector.type"
            )
        return cls(
            type=str(dtype),
            must_not_contain=list(d.get("must_not_contain") or []),
            must_contain=list(d.get("must_contain") or []),
            regex=d.get("regex"),
            negate=bool(d.get("negate", False)),
            canary=d.get("canary"),
            forbidden_tools=list(d.get("forbidden_tools") or []),
            required_tool_absent=bool(d.get("required_tool_absent", False)),
            forbidden_tool_args_regex=d.get("forbidden_tool_args_regex"),
            all_of=[cls.from_dict(x, source_path) for x in all_of_raw],
            any_of=[cls.from_dict(x, source_path) for x in any_of_raw],
        )


@dataclass
class InjectionVector:
    channel: str
    payload: str

    @classmethod
    def from_dict(cls, d: dict, source_path: str = "") -> "InjectionVector":
        channel = d.get("channel")
        if channel not in VALID_CHANNELS:
            raise ScenarioValidationError(
                f"injection_vector.channel must be one of {sorted(VALID_CHANNELS)}",
                source_path,
                "injection_vector.channel",
            )
        payload = d.get("payload")
        if not payload:
            raise ScenarioValidationError(
                "injection_vector.payload is required",
                source_path,
                "injection_vector.payload",
            )
        return cls(channel=str(channel), payload=str(payload))


@dataclass
class AttackScenario:
    id: str
    category: str
    title: str
    description: str
    severity: Severity
    atlas: list[str]
    owasp: list[str]
    attack_prompt: str
    injection_vector: Optional[InjectionVector]
    detector: DetectorSpec
    remediation: str
    system_prompt: Optional[str] = None
    context_documents: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_yaml_dict(cls, d: dict, source_path: str = "") -> "AttackScenario":
        if not isinstance(d, dict):
            raise ScenarioValidationError("scenario must be a mapping", source_path)

        required = ["id", "category", "title", "severity", "attack_prompt", "detector"]
        for key in required:
            if key not in d or d[key] in (None, ""):
                raise ScenarioValidationError(
                    f"missing required field {key!r}", source_path, key
                )

        try:
            severity = Severity.from_str(d["severity"])
        except ValueError as exc:
            raise ScenarioValidationError(
                f"invalid severity {d['severity']!r}: {exc}", source_path, "severity"
            ) from exc

        injection_vector = None
        if d.get("injection_vector"):
            injection_vector = InjectionVector.from_dict(
                d["injection_vector"], source_path
            )

        detector = DetectorSpec.from_dict(d["detector"], source_path)

        return cls(
            id=str(d["id"]),
            category=str(d["category"]),
            title=str(d["title"]),
            description=str(d.get("description", "")),
            severity=severity,
            atlas=list(d.get("atlas") or []),
            owasp=list(d.get("owasp") or []),
            attack_prompt=str(d["attack_prompt"]),
            injection_vector=injection_vector,
            detector=detector,
            remediation=str(d.get("remediation", "")),
            system_prompt=d.get("system_prompt"),
            context_documents=list(d.get("context_documents") or []),
            metadata=dict(d.get("metadata") or {}),
        )
