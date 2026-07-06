"""Google Cloud Vertex AI reasoning-engine agent adapter (scaffold).

Importing this module never fails: the ``google-cloud-aiplatform`` SDK is
imported lazily inside :meth:`VertexAgentAdapter._client`.

Real invocation shape::

    import vertexai
    from vertexai.preview import reasoning_engines
    vertexai.init(project=project, location=location)
    engine = reasoning_engines.ReasoningEngine(reasoning_engine_id)
    result = engine.query(input=request.prompt)

Config keys: project, location, reasoning_engine_id.
Credentials come from Google Application Default Credentials (ADC) -- Morpheus
never reads GCP secrets directly.
"""

from __future__ import annotations

from ..models import AgentRequest, AgentResponse
from .base import AdapterError, MissingDependencyError, TargetAdapter


class VertexAgentAdapter(TargetAdapter):
    name = "vertex"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.project = self.config.get("project")
        self.location = self.config.get("location")
        self.reasoning_engine_id = self.config.get("reasoning_engine_id")

    def _client(self):
        try:
            import vertexai  # noqa: F401
            from vertexai.preview import reasoning_engines  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError(
                "Vertex adapter requires google-cloud-aiplatform: install with "
                "\"pip install 'morpheus[vertex]'\" and configure Google Application "
                "Default Credentials (ADC)."
            ) from exc
        import vertexai
        from vertexai.preview import reasoning_engines

        vertexai.init(project=self.project, location=self.location)
        return reasoning_engines.ReasoningEngine(self.reasoning_engine_id)

    def invoke(self, request: AgentRequest) -> AgentResponse:  # pragma: no cover - live only
        if not self.reasoning_engine_id:
            raise AdapterError("vertex adapter requires reasoning_engine_id")
        engine = self._client()
        result = engine.query(input=request.prompt)
        return AgentResponse(text=str(result))
