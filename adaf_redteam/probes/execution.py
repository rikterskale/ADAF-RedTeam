"""Live SVCCTL execution proof. UNVALIDATED — every method raises.

Proof-of-execution ONLY: the design runs a single fixed benign marker (echo a
nonce) and captures the exit code + echoed marker. It is not a shell and takes no
user-supplied command. The service-create/run/delete primitives are the
lab-certification boundary and are intentionally not implemented.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError("live SVCCTL exec needs the 'kerberos' extra (impacket)") from exc


class LiveSvcctlExec:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def run_marker(self, target: str, marker: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "SVCCTL exec primitive is intentionally not implemented (lab boundary). "
            "It runs only a fixed benign marker, never a user command."
        )

    def remove_service(self, target: str) -> bool:  # pragma: no cover
        raise NotImplementedError("SVCCTL service cleanup primitive is not lab-certified")
