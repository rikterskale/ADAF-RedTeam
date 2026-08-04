"""Load and schema-validate an engagement file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..schemas import load_schema, validate

_SCHEMA_NAME = "engagement.schema.json"


@dataclass(frozen=True)
class Engagement:
    raw: dict
    path: Path

    @property
    def engagement_id(self) -> str:
        return self.raw["engagementId"]

    @property
    def authorized_domains(self) -> list[str]:
        return self.raw["authorizedDomains"]

    @property
    def authorized_source_addresses(self) -> list[str]:
        return self.raw["authorizedSourceAddresses"]

    def capability_authz(self, capability_id: str) -> dict | None:
        return self.raw.get("capabilities", {}).get(capability_id)


def load_engagement(path: str | Path) -> Engagement:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    validate(data, load_schema(_SCHEMA_NAME))
    return Engagement(raw=data, path=path)
