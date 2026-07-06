"""Generic live HTTP adapter using only the standard library (urllib)."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

from ..models import AgentRequest, AgentResponse, ToolCall
from .base import AdapterError, TargetAdapter

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PLACEHOLDER_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.]*)\}")


class GenericHTTPAdapter(TargetAdapter):
    name = "http"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        http = self.config.get("http") or {}
        if not isinstance(http, dict):
            raise AdapterError("config['http'] must be a mapping")
        self.base_url = http.get("base_url")
        if not self.base_url:
            raise AdapterError("http.base_url is required for the http adapter")
        self.method = str(http.get("method", "POST")).upper()
        self.headers = dict(http.get("headers") or {})
        self.timeout_seconds = float(http.get("timeout_seconds", 30))
        self.request_template = http.get("request_template", {"prompt": "${prompt}"})
        mapping = http.get("response_mapping") or {}
        if "text" not in mapping:
            raise AdapterError("http.response_mapping.text (dotted path) is required")
        self.response_mapping = mapping

    # -- public -------------------------------------------------------------
    def invoke(self, request: AgentRequest) -> AgentResponse:
        ctx = {
            "prompt": request.prompt,
            "system": request.system or "",
            "conversation_id": request.conversation_id or "",
            "context_documents": list(request.context_documents or []),
        }
        body_obj = _expand(self.request_template, ctx)
        body_bytes = json.dumps(body_obj).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        for key, value in self.headers.items():
            headers[key] = _resolve_env(str(value))

        req = urllib.request.Request(
            self.base_url, data=body_bytes, headers=headers, method=self.method
        )

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status = resp.getcode()
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:  # non-2xx
            body = _read_error_body(exc)
            raise AdapterError(
                _redact(f"HTTP {exc.code} from {self.base_url}: {body[:500]}")
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AdapterError(
                _redact(f"request to {self.base_url} failed: {exc}")
            ) from exc
        latency_ms = (time.perf_counter() - start) * 1000.0

        if not (200 <= status < 300):
            raise AdapterError(
                _redact(f"HTTP {status} from {self.base_url}: {raw[:500]}")
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterError(
                _redact(f"invalid JSON from {self.base_url}: {raw[:500]}")
            ) from exc

        text_path = self.response_mapping["text"]
        text = _dig(data, text_path)
        if text is None:
            raise AdapterError(
                _redact(
                    f"response_mapping.text path {text_path!r} not found in "
                    f"response: {raw[:500]}"
                )
            )

        tool_calls = self._extract_tool_calls(data)
        conv_path = self.response_mapping.get("conversation_id")
        conversation_id = _dig(data, conv_path) if conv_path else None
        if conversation_id is not None and not isinstance(conversation_id, str):
            conversation_id = str(conversation_id)

        return AgentResponse(
            text=str(text),
            tool_calls=tool_calls,
            raw=data if isinstance(data, dict) else {"data": data},
            latency_ms=latency_ms,
        )

    # -- helpers ------------------------------------------------------------
    def _extract_tool_calls(self, data: Any) -> list[ToolCall]:
        path = self.response_mapping.get("tool_calls")
        if not path:
            return []
        raw_list = _dig(data, path)
        if not isinstance(raw_list, list):
            return []
        name_field = self.response_mapping.get("tool_call_name_field", "name")
        args_field = self.response_mapping.get("tool_call_args_field", "arguments")
        calls: list[ToolCall] = []
        for item in raw_list:
            if isinstance(item, dict):
                name = str(item.get(name_field, ""))
                args = item.get(args_field, {})
                if not isinstance(args, dict):
                    args = {"value": args}
                calls.append(
                    ToolCall(name=name, arguments=args, raw=json.dumps(item, default=str))
                )
            else:
                calls.append(ToolCall(name=str(item), arguments={}, raw=str(item)))
        return calls


def _dig(obj: Any, path: str | None) -> Any:
    """Walk a dotted path over dicts/lists; numeric segments index lists."""
    if path is None:
        return None
    current = obj
    for segment in str(path).split("."):
        if segment == "":
            continue
        if isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isdigit():
                return None
            idx = int(segment)
            if idx < 0 or idx >= len(current):
                return None
            current = current[idx]
        else:
            return None
    return current


def _expand(value: Any, ctx: dict) -> Any:
    """Recursively substitute ``${...}`` placeholders inside strings/containers."""
    if isinstance(value, str):
        return _expand_str(value, ctx)
    if isinstance(value, dict):
        return {k: _expand(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, ctx) for v in value]
    return value


def _expand_str(value: str, ctx: dict) -> Any:
    # Whole-string placeholder: preserve the substituted value's type
    # (e.g. ${context_documents} -> a JSON list).
    whole = _PLACEHOLDER_PATTERN.fullmatch(value.strip())
    if whole:
        key = whole.group(1)
        if key in ctx:
            return ctx[key]

    def repl(match: re.Match) -> str:
        key = match.group(1)
        if key not in ctx:
            return match.group(0)
        sub = ctx[key]
        if isinstance(sub, (list, dict)):
            return json.dumps(sub)
        return str(sub)

    return _PLACEHOLDER_PATTERN.sub(repl, value)


def _resolve_env(value: str) -> str:
    def repl(match: re.Match) -> str:
        return os.environ.get(match.group(1), "")

    return _ENV_PATTERN.sub(repl, value)


_REDACTION_PATTERNS = [
    # JSON/quoted form: "Authorization": "Bearer sk-..." -> keep key, redact value.
    (
        re.compile(r'(?i)("?authorization"?\s*[:=]\s*")[^"]*(")'),
        r"\1<redacted>\2",
    ),
    # Header/plain form: Authorization: Bearer eyJ... (redact through end of line).
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*).*?(?=$|[\r\n])"),
        r"\1<redacted>",
    ),
    # Bearer <token> anywhere.
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]+"), "Bearer <redacted>"),
    # OpenAI-style keys.
    (re.compile(r"\bsk-[A-Za-z0-9._\-]{6,}"), "<redacted>"),
    # Slack tokens.
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{6,}"), "<redacted>"),
    # AWS access key ids.
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}"), "<redacted>"),
    # Any residual ${VAR}-style placeholder (defensive; should be resolved earlier).
    (re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"), "<redacted>"),
]


def _redact(text: str) -> str:
    """Strip secrets from error/debug text before it reaches logs or stderr."""
    if not text:
        return text
    for pattern, repl in _REDACTION_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return str(exc)
