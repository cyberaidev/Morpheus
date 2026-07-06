"""MITRE ATLAS and OWASP LLM Top 10 (2025) reference mappings."""

from __future__ import annotations

ATLAS: dict[str, dict[str, str]] = {
    "AML.T0051": {
        "title": "LLM Prompt Injection",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "AML.T0051.000": {
        "title": "LLM Prompt Injection: Direct",
        "url": "https://atlas.mitre.org/techniques/AML.T0051.000",
    },
    "AML.T0051.001": {
        "title": "LLM Prompt Injection: Indirect",
        "url": "https://atlas.mitre.org/techniques/AML.T0051.001",
    },
    "AML.T0053": {
        "title": "LLM Plugin Compromise",
        "url": "https://atlas.mitre.org/techniques/AML.T0053",
    },
    "AML.T0054": {
        "title": "LLM Jailbreak",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
    },
    "AML.T0056": {
        "title": "LLM Meta Prompt Extraction",
        "url": "https://atlas.mitre.org/techniques/AML.T0056",
    },
    "AML.T0057": {
        "title": "LLM Data Leakage",
        "url": "https://atlas.mitre.org/techniques/AML.T0057",
    },
    "AML.T0020": {
        "title": "Poison Training Data",
        "url": "https://atlas.mitre.org/techniques/AML.T0020",
    },
    "AML.T0059": {
        "title": "Erode Dataset Integrity",
        "url": "https://atlas.mitre.org/techniques/AML.T0059",
    },
    "AML.T0012": {
        "title": "Valid Accounts",
        "url": "https://atlas.mitre.org/techniques/AML.T0012",
    },
}

OWASP: dict[str, dict[str, str]] = {
    "LLM01": {
        "title": "Prompt Injection",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    "LLM02": {
        "title": "Sensitive Information Disclosure",
        "url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    },
    "LLM03": {
        "title": "Supply Chain",
        "url": "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
    },
    "LLM04": {
        "title": "Data and Model Poisoning",
        "url": "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    },
    "LLM05": {
        "title": "Improper Output Handling",
        "url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    "LLM06": {
        "title": "Excessive Agency",
        "url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    },
    "LLM07": {
        "title": "System Prompt Leakage",
        "url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
    "LLM08": {
        "title": "Vector and Embedding Weaknesses",
        "url": "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    },
    "LLM09": {
        "title": "Misinformation",
        "url": "https://genai.owasp.org/llmrisk/llm09-misinformation/",
    },
    "LLM10": {
        "title": "Unbounded Consumption",
        "url": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    },
}


def atlas_entry(technique_id: str) -> dict[str, str]:
    return ATLAS.get(
        technique_id,
        {"title": technique_id, "url": "https://atlas.mitre.org/matrices/atlas"},
    )


def owasp_entry(risk_id: str) -> dict[str, str]:
    return OWASP.get(
        risk_id, {"title": risk_id, "url": "https://genai.owasp.org/"}
    )
