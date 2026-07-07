# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - Unreleased

### Added
- **SARIF 2.1.0 output** (`morpheus run --sarif PATH`) with one rule per
  scenario and one result per failed non-errored finding, mapping severity to
  SARIF levels (critical/high → error, medium → warning, low/info → note).
  Wired into CI for GitHub code scanning.
- **`--dry-run`** for `run`: prints the expanded request body and
  resolved-and-redacted headers for the first selected scenario, then exits
  without touching the network.
- **`--log-responses`** (or `MORPHEUS_LOG_RESPONSES=1`): writes each response,
  redacted, to `<out>/responses/<scenario_id>.json`.
- **`--version`** top-level flag alongside the `version` subcommand.
- **`list --format json`** emitting a scenario-metadata array.
- **HTTP retries with backoff** (`http.retries`, `http.retry_status`,
  `http.backoff_seconds`; default off), honoring `Retry-After`, stdlib only.
- **Progress output**: `run` prints `[i/N] <id>` to stderr per scenario in text
  mode (silent under `--format json`); `Runner.run` accepts an `on_scenario`
  callback.
- **Detector `args_regex_scope`** field (`any` default, or `forbidden`) to scope
  the forbidden-tool-args regex.
- **HTML report filtering**: filter buttons (All / Vulnerable / Secure /
  Errored / by severity), a top "Failed findings" summary table, and an errored
  count — still 100% self-contained.
- Four new `core` scenarios (pack now ships **18**): SSRF to cloud metadata
  (`ta-ssrf-metadata`), encoded system-prompt exfiltration
  (`az-system-prompt-exfil-encoded`), Unicode-obfuscated injection
  (`pi-unicode-injection`), and conversation-history injection
  (`ii-history-injection`).
- Governance docs: `CONTRIBUTING.md`, `SECURITY.md`, `CODEOWNERS`, this
  changelog.
- `pyproject` metadata: `[project.urls]`, trove classifiers, an `all` optional
  extra aggregating cloud SDKs, and `pytest-cov` in the `dev` extra.

### Changed
- **`.env` config layer now works.** `run` applies parsed `.env` values into the
  process environment without overriding already-set `os.environ` keys, so the
  documented precedence (defaults < morpheus.yaml < .env < os.environ < CLI
  flags) actually holds and `${ENV_VAR}` header placeholders resolve tokens that
  live only in `.env`.
- **Detector hardening (fail signals only, polarity preserved).** A shared
  `_normalize` (NFKC fold + zero-width stripping + whitespace collapse) is
  applied so `must_contain`/`must_not_contain`/`regex` also match a normalized
  variant; the canary detector additionally catches base64/rot13 encodings of
  the canary in the response, tool calls, and raw payload.
- **JUnit attributes match emitted elements.** `testsuite` `tests`/`failures`/
  `skipped`/`errors` are computed from the actual `<failure>`/`<skipped>`
  elements; a failed INFO finding is now a real `<failure>` (errored findings
  remain `<skipped>`).
- CI: `ruff check .` is now blocking, tests run with coverage, and a guarded
  SARIF upload step was added.

## [0.1.0] - 2026

### Added
- Initial release: pluggable target adapters (live generic HTTP via `urllib`;
  scaffolded Bedrock/Azure/OpenAI/Vertex with lazy imports; offline
  vulnerable/safe mock), a 14-scenario `core` pack across seven agentic-AI risk
  categories, severity-weighted scoring with a letter grade, MITRE ATLAS +
  OWASP LLM Top 10 (2025) mappings, `scorecard.json` / self-contained
  `report.html` / `junit.xml` outputs, and a severity-gated CI exit code.
