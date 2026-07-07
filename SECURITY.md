# Security Policy

## Reporting a vulnerability

If you discover a security issue in Morpheus itself (the harness, adapters, or
report writers), please report it privately rather than opening a public issue.

- Email: **security@cyberai.dev** *(placeholder — replace with the project's
  real security contact)*
- Please include a description, reproduction steps, and the affected version.
- We aim to acknowledge reports within a few business days and will coordinate
  a fix and disclosure timeline with you.

Do not include real secrets, customer data, or live credentials in a report.

## Threat-model caveat (read this)

Morpheus is a **testing harness**, not a security guarantee. Understand its
limits before relying on a score:

- **It tests observable behavior against a fixed scenario pack.** A passing
  grade means the target resisted *these specific* attacks as written — it does
  **not** mean the agent is secure against attacks outside the pack, novel
  phrasings, or adaptive adversaries.
- **Detectors are heuristic.** They match substrings, regexes, canaries, and
  tool-call shapes (with light normalization and encoding checks). They can be
  evaded and can produce false negatives; a "SECURE" result is evidence, not
  proof.
- **The mock adapter proves the harness, not a real agent.** The vulnerable and
  safe mocks exist to validate that Morpheus scores correctly (vulnerable → all
  fail, safe → all pass). Running against the mock tells you nothing about any
  production system.
- **Scores are relative and pack-versioned.** Compare runs of the same pack
  version against the same target over time; do not treat the number as an
  absolute measure of risk.

Use Morpheus as one signal in a broader security program — alongside threat
modeling, code review, red-teaming, and monitoring — not as a substitute for
them.
