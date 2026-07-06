"""Adapter registry and factory."""

from __future__ import annotations

from .azure_foundry import AzureAIFoundryAdapter
from .base import AdapterError, MissingDependencyError, TargetAdapter
from .bedrock import BedrockAgentAdapter
from .http_generic import GenericHTTPAdapter
from .mock import MockAdapter
from .openai_assistants import OpenAIAssistantsAdapter
from .vertex import VertexAgentAdapter

ADAPTER_REGISTRY: dict[str, type[TargetAdapter]] = {
    "mock": MockAdapter,
    "http": GenericHTTPAdapter,
    "bedrock": BedrockAgentAdapter,
    "azure": AzureAIFoundryAdapter,
    "openai": OpenAIAssistantsAdapter,
    "vertex": VertexAgentAdapter,
}


def get_adapter(name: str, config: dict | None = None) -> TargetAdapter:
    if name not in ADAPTER_REGISTRY:
        raise AdapterError(
            f"unknown target adapter {name!r}; choose from "
            f"{sorted(ADAPTER_REGISTRY)}"
        )
    return ADAPTER_REGISTRY[name](config or {})


__all__ = [
    "ADAPTER_REGISTRY",
    "AdapterError",
    "MissingDependencyError",
    "TargetAdapter",
    "MockAdapter",
    "GenericHTTPAdapter",
    "BedrockAgentAdapter",
    "AzureAIFoundryAdapter",
    "OpenAIAssistantsAdapter",
    "VertexAgentAdapter",
    "get_adapter",
]
