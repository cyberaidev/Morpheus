from morpheus.models import (
    AgentRequest,
    AgentResponse,
    Finding,
    Severity,
    ToolCall,
    to_serializable,
)


def test_severity_rank_and_weight():
    assert Severity.CRITICAL.rank == 4
    assert Severity.INFO.rank == 0
    assert Severity.CRITICAL.weight == 10
    assert Severity.HIGH.weight == 6
    assert Severity.MEDIUM.weight == 3
    assert Severity.LOW.weight == 1
    assert Severity.INFO.weight == 0


def test_severity_comparison():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.INFO <= Severity.LOW


def test_severity_from_str():
    assert Severity.from_str("Critical") is Severity.CRITICAL
    assert Severity.from_str(" high ") is Severity.HIGH


def test_to_serializable_nested():
    resp = AgentResponse(
        text="hi",
        tool_calls=[ToolCall(name="t", arguments={"a": 1})],
        latency_ms=1.5,
    )
    data = to_serializable(resp)
    assert data["text"] == "hi"
    assert data["tool_calls"][0]["name"] == "t"
    assert data["tool_calls"][0]["arguments"] == {"a": 1}


def test_finding_as_dict_enum_serialized():
    f = Finding(
        scenario_id="s1",
        category="c",
        title="t",
        passed=False,
        severity=Severity.HIGH,
        detector_name="d",
        detector_detail="detail",
    )
    d = f.as_dict()
    assert d["severity"] == "high"
    assert d["passed"] is False


def test_agent_request_defaults():
    req = AgentRequest(prompt="p")
    assert req.context_documents == []
    assert req.metadata == {}
    assert req.system is None
