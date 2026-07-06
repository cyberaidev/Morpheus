"""OpenAI Assistants adapter (scaffold).

Importing this module never fails: the ``openai`` SDK is imported lazily inside
:meth:`OpenAIAssistantsAdapter._client`.

Real invocation shape::

    from openai import OpenAI
    client = OpenAI(base_url=base_url)  # api key from OPENAI_API_KEY env
    thread = client.beta.threads.create()
    client.beta.threads.messages.create(thread_id=thread.id, role="user",
                                        content=request.prompt)
    run = client.beta.threads.runs.create_and_poll(thread_id=thread.id,
                                                    assistant_id=assistant_id)
    messages = client.beta.threads.messages.list(thread_id=thread.id)

Config keys: assistant_id, base_url (optional).
Credentials come from the OPENAI_API_KEY environment variable -- Morpheus never
reads the key directly.
"""

from __future__ import annotations

from ..models import AgentRequest, AgentResponse
from .base import AdapterError, MissingDependencyError, TargetAdapter


class OpenAIAssistantsAdapter(TargetAdapter):
    name = "openai"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.assistant_id = self.config.get("assistant_id")
        self.base_url = self.config.get("base_url")

    def _client(self):
        try:
            from openai import OpenAI  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError(
                "OpenAI Assistants adapter requires the openai SDK: install with "
                "\"pip install 'morpheus[openai]'\" and set the OPENAI_API_KEY "
                "environment variable."
            ) from exc
        from openai import OpenAI

        if self.base_url:
            return OpenAI(base_url=self.base_url)
        return OpenAI()

    def invoke(self, request: AgentRequest) -> AgentResponse:  # pragma: no cover - live only
        if not self.assistant_id:
            raise AdapterError("openai adapter requires assistant_id")
        client = self._client()
        thread = client.beta.threads.create()
        client.beta.threads.messages.create(
            thread_id=thread.id, role="user", content=request.prompt
        )
        client.beta.threads.runs.create_and_poll(
            thread_id=thread.id, assistant_id=self.assistant_id
        )
        messages = client.beta.threads.messages.list(thread_id=thread.id)
        text = ""
        for msg in messages.data:
            if msg.role == "assistant":
                text = "".join(
                    part.text.value
                    for part in msg.content
                    if getattr(part, "type", "") == "text"
                )
                break
        return AgentResponse(text=text)
