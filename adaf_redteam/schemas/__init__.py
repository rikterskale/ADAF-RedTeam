"""Schema loading and validation helpers.

Schemas live in the repo-root schemas/ directory so ADAF and other consumers can
read them without importing Python. This module locates and caches them.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover
    raise ImportError("jsonschema is required. Install with: pip install jsonschema") from exc

_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


@functools.cache
def load_schema(name: str) -> dict:
    return json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate(data: dict, schema: dict) -> None:
    """Raise jsonschema.ValidationError on the first problem."""
    Draft202012Validator(schema).validate(data)


def iter_errors(data: dict, schema: dict) -> list[str]:
    v = Draft202012Validator(schema)
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in v.iter_errors(data)]
