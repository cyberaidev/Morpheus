"""Configuration loading and merging.

Resolution order (lowest precedence first):
    defaults < morpheus.yaml < .env < os.environ < CLI flags

The CLI layer applies its own flags last; this module produces the merged
mapping from files and environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml


@dataclass
class Config:
    data: dict = field(default_factory=dict)
    dotenv: dict = field(default_factory=dict)

    def adapter_config(self, target: str) -> dict:
        """Return the config sub-block for a given target adapter name."""
        block = self.data.get(target)
        if isinstance(block, dict):
            return dict(block)
        # Also allow an adapters.<target> nesting.
        adapters = self.data.get("adapters")
        if isinstance(adapters, dict) and isinstance(adapters.get(target), dict):
            return dict(adapters[target])
        return {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def _parse_dotenv(path: str) -> dict:
    result: dict[str, str] = {}
    if not os.path.exists(path):
        return result
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                result[key] = value
    return result


def load(path: Optional[str] = None, dotenv_path: str = ".env") -> Config:
    """Load and merge configuration.

    A missing config file is not an error; defaults are used.

    The parsed ``.env`` mapping is preserved on :attr:`Config.dotenv` so the CLI
    can apply it into the process environment via :func:`apply_dotenv`, honoring
    the documented precedence ``os.environ > .env``.
    """
    data: dict = {}

    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"config file {path} must contain a mapping at the top level")
        data.update(loaded)

    dotenv = _parse_dotenv(dotenv_path)

    # .env then os.environ populate an "env" sub-mapping so adapters can pull
    # environment-style values without leaking secrets into the primary config.
    env_overlay: dict[str, str] = {}
    env_overlay.update(dotenv)
    # os.environ takes precedence over .env for the same key.
    for key, value in os.environ.items():
        env_overlay[key] = value

    existing_env = data.get("env")
    merged_env = dict(existing_env) if isinstance(existing_env, dict) else {}
    merged_env.update(env_overlay)
    data["env"] = merged_env

    return Config(data=data, dotenv=dotenv)


def apply_dotenv(cfg: Config) -> None:
    """Push parsed ``.env`` values into ``os.environ`` without overriding.

    Preserves the documented precedence ``os.environ > .env``: an already-set
    process environment variable always wins over the ``.env`` value. This is
    what makes ``${ENV_VAR}`` placeholders (resolved from ``os.environ`` at
    invoke time) actually see tokens that live only in ``.env``.
    """
    for key, value in cfg.dotenv.items():
        os.environ.setdefault(key, value)
