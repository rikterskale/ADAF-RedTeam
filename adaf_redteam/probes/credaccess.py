"""Live credential-access probes. UNVALIDATED — every method raises.

LiveNtdsDpapiReader opens read-side streams to NTDS.dit and the domain DPAPI
backup key on the DC. The certified implementation MUST stream bytes directly
into caller-provided SecretVault handles and never write a file, take a
snapshot, or perform DRSUAPI replication.
"""

from __future__ import annotations


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "live NTDS/DPAPI reader needs the 'credaccess' extra: pip install -e '.[credaccess]'"
        ) from exc


class LiveNtdsDpapiReader:
    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def read_ntds_stream(self, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "NTDS.dit read primitive is intentionally not implemented (lab boundary). "
            "The certified implementation MUST stream bytes into a SecretVault handle "
            "and MUST NOT write a copy, take a shadow copy, or run DRSUAPI replication."
        )

    def read_dpapi_backup_key(self, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "Domain DPAPI backup-key read primitive is not lab-certified. The certified "
            "implementation MUST stream bytes into a SecretVault handle and MUST NOT "
            "write the key to disk."
        )
