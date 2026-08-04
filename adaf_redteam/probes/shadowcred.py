"""Live Shadow Credentials writer. UNVALIDATED — every method raises.

The primitives that add/remove msDS-KeyCredentialLink and drive PKINIT are the
lab-certification boundary and are intentionally not implemented. The capability's
add -> verify -> remove orchestration and its secret handling are tested against a
fixture writer instead. Any private key or ticket obtained is redacted to a handle
and discarded; it is never exported.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "live Shadow Credentials writer needs the 'kerberos' extra: pip install -e '.[kerberos]'"
        ) from exc


class LiveShadowCredWriter:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def read_keycred(self, target: str):  # pragma: no cover
        raise NotImplementedError("KeyCredentialLink read primitive is not lab-certified")

    def add_keycred(self, target: str):  # pragma: no cover
        raise NotImplementedError(
            "KeyCredentialLink write primitive is intentionally not implemented (lab boundary)"
        )

    def verify_pkinit(self, target: str) -> bool:  # pragma: no cover
        raise NotImplementedError("PKINIT verify primitive is not lab-certified")

    def remove_keycred(self, target: str, key_id: str):  # pragma: no cover
        raise NotImplementedError("KeyCredentialLink restore primitive is not lab-certified")
