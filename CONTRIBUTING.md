# Contributing to Morpheus

Thanks for your interest in improving Morpheus. This guide covers local setup,
the checks your change must pass, and how to extend the scenario pack and
adapters.

## Development setup

Morpheus targets Python 3.10+ and is installed editable into a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The `dev` extra installs `pytest`, `pytest-cov`, and `ruff`. Cloud SDKs are
optional — install `.[all]` (or a single extra like `.[bedrock]`) only if you
are working on a specific cloud adapter.

## Running the checks

Two checks gate every change and must both be green:

```bash
# Tests (add --cov for the coverage report CI runs).
pytest -q
pytest --cov=morpheus --cov-report=term-missing -q

# Lint (blocking in CI).
ruff check .
```

You can also exercise the CLI offline against the mock target:

```bash
python -m morpheus run --target mock                 # vulnerable -> exit 1, 0/F
python -m morpheus run --target mock --config .ci/mock-safe.yaml  # safe -> exit 0, 100/A
```

## Pull-request expectations

- Every behavior change ships with a test. New scenarios and detectors, in
  particular, must have coverage.
- Preserve the core invariants:
  - **pass = secure** polarity everywhere (a detector passes when the agent
    resisted the attack).
  - The mock contract holds: **vulnerable fails every scenario (0/F)** and
    **safe passes every scenario (100/A)**.
  - Cloud adapters import their SDK lazily; importing Morpheus and constructing
    an adapter must never require the SDK.
  - Report writers (JSON/HTML/JUnit/SARIF) and the HTTP adapter use the
    standard library only.
- Keep secrets out of the repo. `morpheus.yaml`, `.env`, and `reports/` are
  gitignored; only `*.example` files are committed. Route any new on-disk or
  log output through `morpheus.adapters.http_generic._redact`.
- Run `ruff check .` and `pytest -q` before pushing.

## Adding a scenario

Scenarios are YAML files under `scenarios/<pack>/<category>/<name>.yaml`. A
scenario declares an id, category (must match the directory), title, severity,
ATLAS/OWASP mappings, an `attack_prompt`, an optional `injection_vector`, a
`detector`, and `remediation`. See existing files for the shape, and the
"Writing your own scenario" section of the README for a full walkthrough.

A new scenario must **fail on the vulnerable mock and pass on the safe mock**.
If it does not, add or adjust a matching trigger in
`src/morpheus/adapters/mock.py` so the vulnerable mock exhibits the insecure
behavior your detector looks for. Update the scenario-count assertions in
`tests/test_scenario_loader.py` and `tests/test_cli.py`.

## Adding an adapter

Adapters implement `morpheus.adapters.base.TargetAdapter` (`invoke(request) ->
AgentResponse`) and register in `morpheus/adapters/__init__.py`. Cloud SDKs must
be imported lazily inside `invoke()` and raise `MissingDependencyError` (naming
the install extra) when absent. See the scaffold adapters and the README
"Writing your own adapter" section.
