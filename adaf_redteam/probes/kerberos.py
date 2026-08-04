"""Live Kerberos probe. UNVALIDATED (methods raise until lab-certified).

Returns only metadata (roastability + encryption type). It never returns, writes,
or exports the crackable AS-REP / TGS blob — that would be secret export.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live Kerberos probe needs the 'kerberos' extra: pip install -e '.[kerberos]'"
        ) from exc


class LiveKerberosProbe:
    def __init__(self, domain: str, *, dc: str | None = None) -> None:
        _require_deps()
        self._domain = domain
        self._dc = dc

    def asrep(self, user: str) -> dict:  # pragma: no cover - live I/O
        raise NotImplementedError(
            "AS-REP metadata probe is not lab-certified. Implement an AS-REQ without "
            "pre-auth, record preauth_required + etype, and DISCARD the encrypted blob."
        )

    def tgs(self, spn: str) -> dict:  # pragma: no cover - live I/O
        raise NotImplementedError(
            "TGS metadata probe is not lab-certified. Implement a bounded TGS-REQ, record "
            "obtained + etype, and DISCARD the ticket blob."
        )
