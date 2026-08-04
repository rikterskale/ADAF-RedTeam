"""Live AD CS probes / mutators. UNVALIDATED — every method raises.

The state-changing primitives (enrollment, relay-to-web-enrollment, revocation)
are the lab-certification boundary and are intentionally not implemented. The
read-side ESC6 config-flag reader is also unimplemented pending a certified
CA-config source. The capabilities' orchestration and secret handling are tested
against fixture sources; issued PFX/private keys are redacted to a handle and
discarded; issuance/revocation records are durable and cannot be undone —
cleanup reports this honestly.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "live AD CS probes need the 'adcs' extra: pip install -e '.[adcs]'"
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


class LiveAdcsConfigReader:
    """ESC6: reads the CA edit-flags. Not lab-certified — raises."""

    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def ca_edit_flags(self, ca: str) -> list[str]:  # pragma: no cover
        raise NotImplementedError(
            "AD CS CA edit-flag reader is not lab-certified (needs certutil GetCAConfig "
            "or msPKI-Enterprise-Oid parse)."
        )


class LiveAdcsRelay:
    """ESC8: coerce + relay to CA web-enrollment. Highest scrutiny — raises."""

    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def esc8_relay(self, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "ESC8 relay-to-web-enrollment primitive is intentionally not implemented (lab boundary)"
        )

    def esc8_revoke(self, ca: str, serial: str) -> bool:  # pragma: no cover
        raise NotImplementedError("ESC8 revocation primitive is not lab-certified")
