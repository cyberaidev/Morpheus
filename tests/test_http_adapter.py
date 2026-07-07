import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from morpheus.adapters.base import AdapterError
from morpheus.adapters.http_generic import (
    GenericHTTPAdapter,
    _dig,
    _expand,
    _redact,
)
from morpheus.models import AgentRequest


class _Handler(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *args):  # silence
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        payload = json.loads(body) if body else {}
        if self.mode == "ok":
            out = {
                "output": {
                    "text": f"echo: {payload.get('input', '')}",
                    "tool_calls": [
                        {"name": "search", "arguments": {"q": "x"}},
                    ],
                },
                "session_id": "sess-123",
            }
            self._send(200, out)
        elif self.mode == "notext":
            self._send(200, {"output": {}})
        elif self.mode == "badjson":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"not json{{{")
        elif self.mode == "error":
            self._send(500, {"error": "boom"})

    def _send(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield httpd, f"http://{host}:{port}/"
    httpd.shutdown()
    thread.join(timeout=2)


def _adapter(url):
    return GenericHTTPAdapter(
        {
            "http": {
                "base_url": url,
                "method": "POST",
                "request_template": {
                    "input": "${prompt}",
                    "documents": "${context_documents}",
                },
                "response_mapping": {
                    "text": "output.text",
                    "tool_calls": "output.tool_calls",
                    "conversation_id": "session_id",
                },
            }
        }
    )


def test_dig_dict_and_list():
    obj = {"a": {"b": [{"c": 42}]}}
    assert _dig(obj, "a.b.0.c") == 42
    assert _dig(obj, "a.b.5.c") is None
    assert _dig(obj, "a.missing") is None


def test_expand_context_documents_yields_list():
    ctx = {"context_documents": ["d1", "d2"], "prompt": "hi"}
    out = _expand({"documents": "${context_documents}", "p": "${prompt}"}, ctx)
    assert out["documents"] == ["d1", "d2"]
    assert out["p"] == "hi"


def test_invoke_success(server):
    _Handler.mode = "ok"
    _, url = server
    resp = _adapter(url).invoke(AgentRequest(prompt="hello", context_documents=["d"]))
    assert resp.text == "echo: hello"
    assert resp.tool_calls[0].name == "search"
    assert resp.latency_ms is not None


def test_invoke_missing_text_raises(server):
    _Handler.mode = "notext"
    _, url = server
    with pytest.raises(AdapterError):
        _adapter(url).invoke(AgentRequest(prompt="hello"))


def test_invoke_bad_json_raises(server):
    _Handler.mode = "badjson"
    _, url = server
    with pytest.raises(AdapterError):
        _adapter(url).invoke(AgentRequest(prompt="hello"))


def test_invoke_http_error_raises(server):
    _Handler.mode = "error"
    _, url = server
    with pytest.raises(AdapterError):
        _adapter(url).invoke(AgentRequest(prompt="hello"))


def test_missing_base_url_raises():
    with pytest.raises(AdapterError):
        GenericHTTPAdapter({"http": {"response_mapping": {"text": "t"}}})


def test_missing_text_mapping_raises():
    with pytest.raises(AdapterError):
        GenericHTTPAdapter({"http": {"base_url": "http://x/", "response_mapping": {}}})


def test_redact_header_form():
    text = "request failed with headers Authorization: Bearer eyJsecret and more"
    out = _redact(text)
    assert "eyJsecret" not in out
    assert "<redacted>" in out


def test_redact_json_form():
    text = 'body was {"Authorization": "Bearer sk-supersecret", "x": 1}'
    out = _redact(text)
    assert "sk-supersecret" not in out
    assert "<redacted>" in out


def test_redact_generic_secret_patterns():
    samples = {
        "token sk-abcdef123456 leaked": "sk-abcdef123456",
        "slack xoxb-123456-abcdef here": "xoxb-123456-abcdef",
        "aws key AKIAIOSFODNN7EXAMPLE seen": "AKIAIOSFODNN7EXAMPLE",
        "unresolved ${AGENT_API_TOKEN} placeholder": "${AGENT_API_TOKEN}",
        "raw Bearer eyJraw.token.here in log": "eyJraw.token.here",
    }
    for text, secret in samples.items():
        out = _redact(text)
        assert secret not in out, text
        assert "<redacted>" in out, text


class _FlakyHandler(BaseHTTPRequestHandler):
    """Fails with 503 a fixed number of times, then succeeds with 200."""

    remaining_failures = 0

    def log_message(self, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if _FlakyHandler.remaining_failures > 0:
            _FlakyHandler.remaining_failures -= 1
            body = json.dumps({"error": "unavailable"}).encode("utf-8")
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        out = json.dumps({"output": {"text": "recovered"}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def flaky_server():
    httpd = HTTPServer(("127.0.0.1", 0), _FlakyHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield httpd, f"http://{host}:{port}/"
    httpd.shutdown()
    thread.join(timeout=2)


def test_retries_recover_after_transient_503(flaky_server, monkeypatch):
    import morpheus.adapters.http_generic as http_mod

    # Keep the test deterministic and fast: no real sleeping.
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_a, **_k: None)
    _, url = flaky_server
    _FlakyHandler.remaining_failures = 2  # fail 2x, then succeed
    adapter = GenericHTTPAdapter(
        {
            "http": {
                "base_url": url,
                "response_mapping": {"text": "output.text"},
                "retries": 2,
                "backoff_seconds": 0.01,
            }
        }
    )
    resp = adapter.invoke(AgentRequest(prompt="hello"))
    assert resp.text == "recovered"
    assert _FlakyHandler.remaining_failures == 0


def test_retries_exhausted_raises(flaky_server, monkeypatch):
    import morpheus.adapters.http_generic as http_mod

    monkeypatch.setattr(http_mod.time, "sleep", lambda *_a, **_k: None)
    _, url = flaky_server
    _FlakyHandler.remaining_failures = 5  # more failures than retries allow
    adapter = GenericHTTPAdapter(
        {
            "http": {
                "base_url": url,
                "response_mapping": {"text": "output.text"},
                "retries": 1,
                "backoff_seconds": 0.01,
            }
        }
    )
    with pytest.raises(AdapterError):
        adapter.invoke(AgentRequest(prompt="hello"))


def test_default_no_retries(flaky_server, monkeypatch):
    import morpheus.adapters.http_generic as http_mod

    monkeypatch.setattr(http_mod.time, "sleep", lambda *_a, **_k: None)
    _, url = flaky_server
    _FlakyHandler.remaining_failures = 1
    adapter = _adapter(url)  # retries default 0
    with pytest.raises(AdapterError):
        adapter.invoke(AgentRequest(prompt="hello"))
