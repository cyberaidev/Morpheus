import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from morpheus.adapters.http_generic import GenericHTTPAdapter
from morpheus.config import apply_dotenv
from morpheus.config import load as load_config
from morpheus.models import AgentRequest


def test_apply_dotenv_does_not_override_os_environ(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_TOKEN=from_dotenv\nOTHER=dotenv_other\n")
    monkeypatch.chdir(tmp_path)
    # os.environ already has MY_TOKEN -> it must win over .env.
    monkeypatch.setenv("MY_TOKEN", "from_environ")
    monkeypatch.delenv("OTHER", raising=False)

    cfg = load_config(None)
    apply_dotenv(cfg)

    import os

    assert os.environ["MY_TOKEN"] == "from_environ"  # os.environ wins
    assert os.environ["OTHER"] == "dotenv_other"  # .env fills the gap


class _EchoHeaderHandler(BaseHTTPRequestHandler):
    captured = {}

    def log_message(self, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        _EchoHeaderHandler.captured["Authorization"] = self.headers.get("Authorization")
        out = json.dumps({"output": {"text": "ok"}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def header_server():
    httpd = HTTPServer(("127.0.0.1", 0), _EchoHeaderHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield httpd, f"http://{host}:{port}/"
    httpd.shutdown()
    thread.join(timeout=2)


def test_dotenv_token_reaches_outgoing_request(tmp_path, monkeypatch, header_server):
    _, url = header_server
    # Token lives ONLY in .env (never exported).
    env_file = tmp_path / ".env"
    env_file.write_text("MY_TOKEN=secret-dotenv-token\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MY_TOKEN", raising=False)

    cfg = load_config(None)
    apply_dotenv(cfg)  # push .env into os.environ (without overriding)

    adapter = GenericHTTPAdapter(
        {
            "http": {
                "base_url": url,
                "headers": {"Authorization": "Bearer ${MY_TOKEN}"},
                "response_mapping": {"text": "output.text"},
            }
        }
    )
    _EchoHeaderHandler.captured.clear()
    adapter.invoke(AgentRequest(prompt="hi"))
    assert _EchoHeaderHandler.captured["Authorization"] == "Bearer secret-dotenv-token"
