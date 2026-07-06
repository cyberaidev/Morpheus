"""Target-adapter base classes and errors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import AgentRequest, AgentResponse


class AdapterError(RuntimeError):
    """Raised when a target adapter fails to obtain a valid response."""


class MissingDependencyError(AdapterError):
    """Raised when an optional SDK/dependency is not installed."""


class TargetAdapter(ABC):
    """Pluggable interface for invoking a cloud-deployed agent."""

    name: str = "base"

    def __init__(self, config: dict | None = None):
        self.config: dict = dict(config or {})

    @abstractmethod
    def invoke(self, request: AgentRequest) -> AgentResponse:
        """Send ``request`` to the target agent and return its response."""
        raise NotImplementedError

    def close(self) -> None:  # noqa: B027 - intentional no-op default
        """Release any resources held by the adapter."""
        return None
