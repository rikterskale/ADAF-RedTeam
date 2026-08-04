"""Live coercion + relay. UNVALIDATED — every method raises.

Highest scrutiny. Coercion triggers a single named target to authenticate to a
short-lived listener; relay forwards that authentication to LDAP to write a
shadow credential, which is then REMOVED (reversible). No persistent listener, no
second destination, single named target only. All primitives are the
lab-certification boundary and are intentionally not implemented.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError("live coercion/relay needs the 'relay' extra") from exc


class LiveCoercer:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def trigger(self, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Coercion primitive (PetitPotam/PrinterBug) is intentionally not implemented (lab boundary)"
        )


class LiveRelay:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def coerce_and_relay(self, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "SMB->LDAP relay primitive is intentionally not implemented (lab boundary)"
        )

    def remove_shadowcred(self, target: str) -> bool:  # pragma: no cover
        raise NotImplementedError("relay shadow-cred cleanup primitive is not lab-certified")
