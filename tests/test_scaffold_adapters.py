"""Scaffold adapters must import cleanly and raise MissingDependencyError lazily."""

import builtins

import pytest

from morpheus.adapters import (
    AzureAIFoundryAdapter,
    BedrockAgentAdapter,
    OpenAIAssistantsAdapter,
    VertexAgentAdapter,
    get_adapter,
)
from morpheus.adapters.base import MissingDependencyError
from morpheus.models import AgentRequest


def _force_import_error(monkeypatch, *blocked):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        for b in blocked:
            if name == b or name.startswith(b + "."):
                raise ImportError(f"blocked {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_registry_constructs_all_scaffolds():
    for name in ("bedrock", "azure", "openai", "vertex"):
        adapter = get_adapter(name, {})
        assert adapter.name == name


def test_bedrock_missing_dependency(monkeypatch):
    _force_import_error(monkeypatch, "boto3")
    adapter = BedrockAgentAdapter({"agent_id": "a", "agent_alias_id": "b"})
    with pytest.raises(MissingDependencyError) as exc:
        adapter.invoke(AgentRequest(prompt="hi"))
    assert "morpheus[bedrock]" in str(exc.value)


def test_azure_missing_dependency(monkeypatch):
    _force_import_error(monkeypatch, "azure")
    adapter = AzureAIFoundryAdapter({"project_endpoint": "e", "agent_id": "a"})
    with pytest.raises(MissingDependencyError) as exc:
        adapter.invoke(AgentRequest(prompt="hi"))
    assert "morpheus[azure]" in str(exc.value)


def test_openai_missing_dependency(monkeypatch):
    _force_import_error(monkeypatch, "openai")
    adapter = OpenAIAssistantsAdapter({"assistant_id": "a"})
    with pytest.raises(MissingDependencyError) as exc:
        adapter.invoke(AgentRequest(prompt="hi"))
    assert "morpheus[openai]" in str(exc.value)


def test_vertex_missing_dependency(monkeypatch):
    _force_import_error(monkeypatch, "vertexai", "google")
    adapter = VertexAgentAdapter(
        {"project": "p", "location": "l", "reasoning_engine_id": "r"}
    )
    with pytest.raises(MissingDependencyError) as exc:
        adapter.invoke(AgentRequest(prompt="hi"))
    assert "morpheus[vertex]" in str(exc.value)
