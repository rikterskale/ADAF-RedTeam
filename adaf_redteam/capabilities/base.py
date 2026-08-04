"""The Capability abstract base class.

Every capability implements three phases:
  plan()    -> describe exactly what execute() would do. No side effects, ever.
  execute() -> perform the bounded action against an authorized target.
  cleanup() -> reverse any state change and verify reversal.

Phase 0 ships no concrete subclasses. The base exists so the CLI, gate, and
bridge are testable and so later phases have one shape to conform to.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..redaction import SecretVault

if TYPE_CHECKING:
    from ..authz.gates import AuthorizedAction


@dataclass
class CapabilityResult:
    verdict: str  # Confirmed | NotExploitable | Inconclusive | BlockedByGate
    proof_class: str
    assertions: list[str] = field(default_factory=list)
    redacted_refs: dict = field(default_factory=dict)
    detection: dict | None = None
    cleanup: dict | None = None


class Capability(abc.ABC):
    """Base for all capabilities. Subclasses are added in later phases."""

    def __init__(self, action: AuthorizedAction, vault: SecretVault, *,
                 domain: str | None = None, source=None) -> None:
        self.action = action
        self.vault = vault
        self.domain = domain
        # `source` is an injectable dependency (e.g. a DirectorySource). Live runs
        # leave it None and the capability builds its own; tests inject a fake.
        self.source = source

    @abc.abstractmethod
    def plan(self) -> dict:
        """Return a JSON-serializable plan. Must have no side effects."""

    @abc.abstractmethod
    def execute(self) -> CapabilityResult:
        """Perform the bounded action. Secrets must go through self.vault."""

    def cleanup(self) -> dict:
        """Reverse any state change and verify. Override for state-changing caps."""
        return {"required": False, "performed": False, "verified": True, "durableResidue": []}
