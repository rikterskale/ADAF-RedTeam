"""Live Kerberos ticket forgery (golden/silver). UNVALIDATED — methods raise.

Forgery takes a secret key (krbtgt or service account hash) as INPUT; that secret
is redacted to a handle by the capability and never exported, and the forged
ticket is likewise redacted and discarded. The forge primitive is the
lab-certification boundary and is intentionally not implemented.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError("live ticket forgery needs the 'kerberos' extra (impacket)") from exc


class LiveTicketForge:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def forge_and_auth(self, principal: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Golden/silver ticket forge primitive is intentionally not implemented (lab boundary)"
        )
