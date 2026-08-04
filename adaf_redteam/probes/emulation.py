"""Live adversary-emulation / evasion probe. UNVALIDATED — methods raise.

Purple-team framing: emulation runs authorized TTPs and reports DETECTION
evidence (what was attempted, what fired, what did not). The novel evasion and
payload-reliability primitives are the lab-certification boundary and are
intentionally not implemented — there is no 'succeed silently' path.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError("live emulation needs the 'kerberos' extra") from exc


class LiveEmulator:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def emulate(self, target: str, technique: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Adversary-emulation/evasion primitive is intentionally not implemented (lab boundary)"
        )

    def reliability(self, target: str, technique: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Payload-reliability primitive is intentionally not implemented (lab boundary)"
        )
