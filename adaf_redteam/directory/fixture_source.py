"""A fixture-backed DirectorySource.

Lets the full execute -> analyze -> bridge pipeline run offline against known ACE
data, for unit tests and for lab dry-runs before the live collector is certified.
Never touches a network.

Fixture JSON shape:
{
  "domain_acl":  [{"trustee": "...", "right": "...", "object_type": null, "effect": "Allow"}, ...],
  "object_acl":  [ ... same shape ... ],
  "gmsa_readers": ["S-1-5-..."]
}
"""

from __future__ import annotations

import json
from pathlib import Path

from .acl import Ace


def _to_aces(rows: list[dict]) -> list[Ace]:
    return [
        Ace(
            trustee=r["trustee"],
            right=r["right"],
            object_type=r.get("object_type"),
            effect=r.get("effect", "Allow"),
        )
        for r in rows
    ]


class FixtureDirectorySource:
    """Offline source implementing DirectorySource + the Kerberos/Netlogon probe
    methods, so every Phase 1 capability can run against a single fixture file.
    """

    def __init__(self, data: dict) -> None:
        self._domain_acl = _to_aces(data.get("domain_acl", []))
        self._object_acl = _to_aces(data.get("object_acl", []))
        self._gmsa_readers = list(data.get("gmsa_readers", []))
        self._asrep = dict(data.get("asrep", {}))
        self._tgs = dict(data.get("tgs", {}))
        self._zerologon = dict(data.get("zerologon", {}))

    @classmethod
    def from_file(cls, path: str | Path) -> FixtureDirectorySource:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    # DirectorySource
    def domain_acl(self, domain: str) -> list[Ace]:
        return self._domain_acl

    def object_acl(self, dn: str, *, attribute: str | None = None) -> list[Ace]:
        return self._object_acl

    def gmsa_readers(self, dn: str) -> list[str]:
        return self._gmsa_readers

    # KerberosProbe (metadata only; default = not exposed)
    def asrep(self, user: str) -> dict:
        return self._asrep.get(user, {"preauth_required": True})

    def tgs(self, spn: str) -> dict:
        return self._tgs.get(spn, {"obtained": False})

    # NetlogonProbe (detection only; default = patched)
    def zerologon_detect(self, dc: str, max_attempts: int = 2000) -> dict:
        return self._zerologon or {"accepted_zero_auth": False, "attempts_used": max_attempts}
