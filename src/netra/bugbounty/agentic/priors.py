"""Tech-stack priors for the planner."""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any


PRIORS_PATH = Path("data") / "vuln_class_priors.yaml"


@lru_cache(maxsize=1)
def load_priors() -> dict[str, Any]:
    if not PRIORS_PATH.exists():
        return {}
    return json.loads(PRIORS_PATH.read_text(encoding="utf-8"))


def reload_priors() -> dict[str, Any]:
    load_priors.cache_clear()
    return load_priors()
