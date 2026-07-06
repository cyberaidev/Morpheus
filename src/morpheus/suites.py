"""Discover scenario packs and load/filter scenarios."""

from __future__ import annotations

import os
from typing import Optional

import yaml

from .scenario import AttackScenario, ScenarioValidationError

DEFAULT_PACK = "core"


def _scenarios_root() -> str:
    """Locate the top-level ``scenarios/`` directory.

    Falls back from the installed package location up to the repository root.
    """
    env = os.environ.get("MORPHEUS_SCENARIOS_DIR")
    if env and os.path.isdir(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    # src/morpheus -> src -> repo root
    candidates = [
        os.path.join(here, "..", "..", "scenarios"),
        os.path.join(here, "..", "scenarios"),
        os.path.join(os.getcwd(), "scenarios"),
    ]
    for cand in candidates:
        cand = os.path.abspath(cand)
        if os.path.isdir(cand):
            return cand
    return os.path.abspath(candidates[0])


def pack_dir(pack: str = DEFAULT_PACK) -> str:
    return os.path.join(_scenarios_root(), pack)


def list_categories(pack: str = DEFAULT_PACK) -> list[str]:
    root = pack_dir(pack)
    if not os.path.isdir(root):
        return []
    cats = []
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if os.path.isdir(full):
            cats.append(entry)
    return cats


def load_scenarios(
    pack: str = DEFAULT_PACK, suites: Optional[list[str]] = None
) -> list[AttackScenario]:
    """Load scenarios from ``pack``; optionally filter by category names.

    ``suites`` may contain category names or ``"all"``. ``None`` or an empty
    list means all categories.
    """
    root = pack_dir(pack)
    if not os.path.isdir(root):
        raise FileNotFoundError(f"pack directory not found: {root}")

    wanted = None
    if suites:
        lowered = {s.lower() for s in suites}
        if "all" not in lowered:
            wanted = lowered

    scenarios: list[AttackScenario] = []
    seen_ids: dict[str, str] = {}

    for category in list_categories(pack):
        if wanted is not None and category.lower() not in wanted:
            continue
        cat_dir = os.path.join(root, category)
        for fname in sorted(os.listdir(cat_dir)):
            if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                continue
            if fname == "pack.yaml":
                continue
            path = os.path.join(cat_dir, fname)
            with open(path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            scenario = AttackScenario.from_yaml_dict(doc, source_path=path)
            if scenario.category != category:
                raise ScenarioValidationError(
                    f"scenario category {scenario.category!r} does not match "
                    f"directory {category!r}",
                    path,
                    "category",
                )
            if scenario.id in seen_ids:
                raise ScenarioValidationError(
                    f"duplicate scenario id {scenario.id!r} (also in "
                    f"{seen_ids[scenario.id]})",
                    path,
                    "id",
                )
            seen_ids[scenario.id] = path
            scenarios.append(scenario)

    return scenarios
