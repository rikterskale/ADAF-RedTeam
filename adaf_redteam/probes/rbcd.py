"""Live RBCD mutation writer. UNVALIDATED — every method raises.

The write/verify/restore primitives that actually mutate
msDS-AllowedToActOnBehalfOfOtherIdentity and drive S4U are the lab-certification
boundary and are intentionally not implemented here. The capability's mutate ->
verify -> restore orchestration, journal, and cleanup latch are built and tested
against a fixture writer instead.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "live RBCD writer needs the 'kerberos' extra (impacket): pip install -e '.[kerberos]'"
        ) from exc


class LiveRbcdWriter:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def read_rbcd(self, target: str):  # pragma: no cover
        raise NotImplementedError("RBCD read primitive is not lab-certified")

    def write_rbcd(self, target: str, principal: str):  # pragma: no cover
        raise NotImplementedError(
            "RBCD write primitive is intentionally not implemented (lab-certification boundary)"
        )

    def verify_s4u(self, target: str, principal: str) -> bool:  # pragma: no cover
        raise NotImplementedError("RBCD S4U verify primitive is not lab-certified")

    def clear_rbcd(self, target: str, *, restore_to):  # pragma: no cover
        raise NotImplementedError("RBCD restore primitive is not lab-certified")
