"""Execute scenarios against a target adapter and collect findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .adapters.base import AdapterError, TargetAdapter
from .detectors import run_detector
from .models import AgentRequest, Finding, Severity
from .scenario import AttackScenario

# Signature: on_scenario(index_1_based, total, scenario) -> None
ProgressCallback = Callable[[int, int, AttackScenario], None]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RunResult:
    findings: list[Finding]
    target_name: str
    pack_name: str
    started_at: str
    finished_at: str = ""
    scenarios_run: int = field(default=0)


class Runner:
    def __init__(self, adapter: Optional[TargetAdapter] = None):
        self.adapter = adapter

    def run(
        self,
        scenarios: list[AttackScenario],
        pack_name: str = "core",
        on_scenario: Optional[ProgressCallback] = None,
    ) -> RunResult:
        ordered = sorted(scenarios, key=lambda s: (s.category, s.id))
        started_at = _now_iso()
        findings: list[Finding] = []

        total = len(ordered)
        for index, scenario in enumerate(ordered, start=1):
            if on_scenario is not None:
                on_scenario(index, total, scenario)
            findings.append(self._run_one(scenario))

        return RunResult(
            findings=findings,
            target_name=getattr(self.adapter, "name", "unknown"),
            pack_name=pack_name,
            started_at=started_at,
            finished_at=_now_iso(),
            scenarios_run=len(ordered),
        )

    # -- public -------------------------------------------------------------
    def build_request(self, scenario: AttackScenario) -> AgentRequest:
        """Build the :class:`AgentRequest` for ``scenario`` (no network).

        Exposed so callers (e.g. the CLI ``--dry-run`` path) can inspect the
        exact request that would be sent without invoking an adapter.
        """
        return self._build_request(scenario)

    # -- internals ----------------------------------------------------------
    def _build_request(self, scenario: AttackScenario) -> AgentRequest:
        prompt = scenario.attack_prompt
        context_documents = list(scenario.context_documents)
        metadata = dict(scenario.metadata)

        vector = scenario.injection_vector
        if vector is not None:
            channel = vector.channel
            if channel == "prompt":
                prompt = vector.payload
            elif channel == "context_document":
                context_documents.append(vector.payload)
            elif channel == "tool_output":
                metadata["tool_output"] = vector.payload
            elif channel == "conversation_history":
                metadata["conversation_history"] = vector.payload

        # Surface the detector canary in metadata so mock/canary detectors align.
        if scenario.detector.canary and "canary" not in metadata:
            metadata["canary"] = scenario.detector.canary

        return AgentRequest(
            prompt=prompt,
            system=scenario.system_prompt,
            context_documents=context_documents,
            metadata=metadata,
            conversation_id=scenario.id,
        )

    def _run_one(self, scenario: AttackScenario) -> Finding:
        request = self._build_request(scenario)
        try:
            response = self.adapter.invoke(request)
        except AdapterError as exc:
            # An adapter/network error is neither a pass (agent resisted) nor a
            # fail (attack succeeded): mark it as errored so it is excluded from
            # the score, the gate, and the passed/failed counts.
            return Finding(
                scenario_id=scenario.id,
                category=scenario.category,
                title=scenario.title,
                passed=False,
                severity=Severity.INFO,
                detector_name=scenario.detector.type,
                detector_detail=f"adapter error: {exc}",
                atlas=list(scenario.atlas),
                owasp=list(scenario.owasp),
                remediation=scenario.remediation,
                request_prompt=request.prompt,
                response_excerpt="",
                latency_ms=None,
                errored=True,
            )

        result = run_detector(scenario.detector, response)
        return Finding(
            scenario_id=scenario.id,
            category=scenario.category,
            title=scenario.title,
            passed=result.passed,
            severity=scenario.severity,
            detector_name=scenario.detector.type,
            detector_detail=result.detail,
            atlas=list(scenario.atlas),
            owasp=list(scenario.owasp),
            remediation=scenario.remediation,
            request_prompt=request.prompt,
            response_excerpt=(response.text or "")[:500],
            latency_ms=response.latency_ms,
        )
