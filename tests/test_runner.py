from morpheus.adapters.base import AdapterError, TargetAdapter
from morpheus.adapters.mock import MockAdapter
from morpheus.models import AgentResponse, Severity
from morpheus.runner import Runner
from morpheus.scenario import AttackScenario, DetectorSpec, InjectionVector


class _RaisingAdapter(TargetAdapter):
    name = "raising"

    def invoke(self, request):
        raise AdapterError("simulated failure")


class _RecordingAdapter(TargetAdapter):
    name = "recording"

    def __init__(self, config=None):
        super().__init__(config)
        self.last_request = None

    def invoke(self, request):
        self.last_request = request
        return AgentResponse(text="clean", tool_calls=[])


def _scenario(**kw):
    base = dict(
        id="s1",
        category="prompt_injection",
        title="t",
        description="d",
        severity=Severity.HIGH,
        atlas=["AML.T0051.000"],
        owasp=["LLM01"],
        attack_prompt="benign prompt",
        injection_vector=None,
        detector=DetectorSpec(type="must_not_contain", must_not_contain=["INJECTION-OK"]),
        remediation="fix it",
    )
    base.update(kw)
    return AttackScenario(**base)


def test_adapter_error_becomes_errored_not_pass():
    result = Runner(_RaisingAdapter()).run([_scenario()])
    f = result.findings[0]
    assert f.errored is True
    assert f.passed is False
    assert f.severity == Severity.INFO
    assert "adapter error" in f.detector_detail


def test_runner_sorts_by_category_and_id():
    s_a = _scenario(id="b", category="tool_abuse")
    s_b = _scenario(id="a", category="prompt_injection")
    result = Runner(MockAdapter({"mode": "safe"})).run([s_a, s_b])
    order = [(f.category, f.scenario_id) for f in result.findings]
    assert order == sorted(order)


def test_prompt_injection_vector_replaces_prompt():
    adapter = _RecordingAdapter()
    scenario = _scenario(
        injection_vector=InjectionVector(channel="prompt", payload="PAYLOAD-XYZ")
    )
    Runner(adapter).run([scenario])
    assert adapter.last_request.prompt == "PAYLOAD-XYZ"


def test_context_document_vector_appends_doc():
    adapter = _RecordingAdapter()
    scenario = _scenario(
        context_documents=["orig"],
        injection_vector=InjectionVector(
            channel="context_document", payload="INJECTED"
        ),
    )
    Runner(adapter).run([scenario])
    assert "INJECTED" in adapter.last_request.context_documents
    assert "orig" in adapter.last_request.context_documents


def test_run_result_timestamps_and_counts():
    result = Runner(MockAdapter({"mode": "safe"})).run([_scenario()])
    assert result.started_at
    assert result.finished_at
    assert result.scenarios_run == 1
    assert result.target_name == "mock"


def test_on_scenario_callback_fires_n_times():
    scenarios = [
        _scenario(id="a", category="prompt_injection"),
        _scenario(id="b", category="tool_abuse"),
        _scenario(id="c", category="unsafe_autonomy"),
    ]
    seen = []

    def cb(index, total, scenario):
        seen.append((index, total, scenario.id))

    Runner(MockAdapter({"mode": "safe"})).run(scenarios, on_scenario=cb)
    assert len(seen) == 3
    assert [s[0] for s in seen] == [1, 2, 3]
    assert all(s[1] == 3 for s in seen)


def test_build_request_public_no_adapter():
    scenario = _scenario(
        injection_vector=InjectionVector(channel="prompt", payload="PAYLOAD-XYZ")
    )
    request = Runner().build_request(scenario)
    assert request.prompt == "PAYLOAD-XYZ"
