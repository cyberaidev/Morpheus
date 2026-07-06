"""AWS Bedrock Agents adapter (scaffold).

Importing this module never fails: the ``boto3`` SDK is imported lazily inside
:meth:`BedrockAgentAdapter._client` so CI passes with no SDK installed.

Real invocation shape::

    import boto3
    client = boto3.client("bedrock-agent-runtime", region_name=region)
    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=agent_alias_id,
        sessionId=session_id,
        inputText=request.prompt,
    )
    # response["completion"] is an event stream of chunks.

Config keys: agent_id, agent_alias_id, region, session_id (optional).
Credentials come from the standard boto3 credential chain -- Morpheus never
reads AWS secrets directly.
"""

from __future__ import annotations

from ..models import AgentRequest, AgentResponse, ToolCall
from .base import AdapterError, MissingDependencyError, TargetAdapter


class BedrockAgentAdapter(TargetAdapter):
    name = "bedrock"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.agent_id = self.config.get("agent_id")
        self.agent_alias_id = self.config.get("agent_alias_id")
        self.region = self.config.get("region")
        self.session_id = self.config.get("session_id", "morpheus-session")

    def _client(self):
        try:
            import boto3  # noqa: F401  (lazy import by design)
        except ImportError as exc:
            raise MissingDependencyError(
                "AWS Bedrock adapter requires boto3: install with "
                "\"pip install 'morpheus[bedrock]'\" and configure AWS credentials "
                "(via the standard boto3 credential chain)."
            ) from exc
        return boto3.client("bedrock-agent-runtime", region_name=self.region)

    def invoke(self, request: AgentRequest) -> AgentResponse:
        if not self.agent_id or not self.agent_alias_id:
            raise AdapterError("bedrock adapter requires agent_id and agent_alias_id")
        client = self._client()
        response = client.invoke_agent(
            agentId=self.agent_id,
            agentAliasId=self.agent_alias_id,
            sessionId=request.conversation_id or self.session_id,
            inputText=request.prompt,
        )
        text_chunks: list[str] = []
        tool_calls: list[ToolCall] = []
        for event in response.get("completion", []):  # pragma: no cover - live only
            chunk = event.get("chunk")
            if chunk and chunk.get("bytes"):
                text_chunks.append(chunk["bytes"].decode("utf-8", errors="replace"))
        return AgentResponse(text="".join(text_chunks), tool_calls=tool_calls)
