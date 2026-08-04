"""Live Netlogon probe for SAFE Zerologon detection. UNVALIDATED (methods raise).

Detection only: it attempts ComputeNetlogonCredential with a zero client
challenge a bounded number of times and observes whether the DC accepts it. It
STOPS before NetrServerPasswordSet2 — it never calls the password-set operation,
so it cannot modify the machine account. The destructive reset lives only in the
separate zerologon-reset capability (which is lab-only and whose primitive is
intentionally not implemented).
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live Netlogon probe needs the 'kerberos' extra (impacket): pip install -e '.[kerberos]'"
        ) from exc


class LiveNetlogonProbe:
    def __init__(self, dc: str) -> None:
        _require_deps()
        self._dc = dc

    def zerologon_detect(self, dc: str, max_attempts: int = 2000) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Zerologon SAFE detection is not lab-certified. Implement bounded "
            "ComputeNetlogonCredential(zero-challenge) attempts and STOP before "
            "NetrServerPasswordSet2 — never modify the machine account here."
        )
