"""Azure AI Foundry (AI Projects) agent adapter (scaffold).

Importing this module never fails: the Azure SDKs are imported lazily inside
:meth:`AzureAIFoundryAdapter._client`.

Real invocation shape::

    from azure.ai.projects import AIProjectClient
    from azure.identity import DefaultAzureCredential
    client = AIProjectClient(endpoint=project_endpoint,
                             credential=DefaultAzureCredential())
    thread = client.agents.threads.create()
    client.agents.messages.create(thread_id=thread.id, role="user",
                                  content=request.prompt)
    run = client.agents.runs.create_and_process(thread_id=thread.id,
                                                 agent_id=agent_id)
    messages = client.agents.messages.list(thread_id=thread.id)

Config keys: project_endpoint, agent_id, model_deployment (optional).
Credentials come from DefaultAzureCredential -- Morpheus never reads secrets.
"""

from __future__ import annotations

from ..models import AgentRequest, AgentResponse
from .base import AdapterError, MissingDependencyError, TargetAdapter


class AzureAIFoundryAdapter(TargetAdapter):
    name = "azure"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.project_endpoint = self.config.get("project_endpoint")
        self.agent_id = self.config.get("agent_id")
        self.model_deployment = self.config.get("model_deployment")

    def _client(self):
        try:
            from azure.ai.projects import AIProjectClient  # noqa: F401
            from azure.identity import DefaultAzureCredential  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError(
                "Azure AI Foundry adapter requires azure-ai-projects and "
                "azure-identity: install with \"pip install 'morpheus[azure]'\" and "
                "configure Azure credentials (DefaultAzureCredential)."
            ) from exc
        from azure.ai.projects import AIProjectClient
        from azure.identity import DefaultAzureCredential

        return AIProjectClient(
            endpoint=self.project_endpoint, credential=DefaultAzureCredential()
        )

    def invoke(self, request: AgentRequest) -> AgentResponse:  # pragma: no cover - live only
        if not self.project_endpoint or not self.agent_id:
            raise AdapterError("azure adapter requires project_endpoint and agent_id")
        client = self._client()
        thread = client.agents.threads.create()
        client.agents.messages.create(
            thread_id=thread.id, role="user", content=request.prompt
        )
        client.agents.runs.create_and_process(
            thread_id=thread.id, agent_id=self.agent_id
        )
        messages = client.agents.messages.list(thread_id=thread.id)
        text = ""
        for msg in messages:
            if getattr(msg, "role", None) == "assistant":
                text = str(getattr(msg, "content", ""))
                break
        return AgentResponse(text=text)
