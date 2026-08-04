"""Live AD CS ESC1 enroller. UNVALIDATED — every method raises.

The enrollment (arbitrary-SAN certificate request) and revocation primitives are
the lab-certification boundary and are intentionally not implemented. The
capability's enroll -> authenticate -> revoke orchestration and its PFX handling
are tested against a fixture enroller. The issued PFX/private key is redacted to a
handle and discarded; it is never exported. Issuance/revocation records are
durable and cannot be undone — cleanup reports this honestly.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "live AD CS enroller needs the 'adcs' extra: pip install -e '.[adcs]'"
        ) from exc


class LiveAdcsEnroller:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def enroll(self, ca: str, *, requested_san: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "AD CS ESC1 enrollment primitive is intentionally not implemented (lab boundary)"
        )

    def revoke(self, ca: str, serial: str) -> bool:  # pragma: no cover
        raise NotImplementedError("AD CS revocation primitive is not lab-certified")
