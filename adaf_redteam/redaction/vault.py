"""In-memory secret vault. The only door from a raw secret to anything else.

Design rules (enforced by tests/test_redaction.py):
- A raw secret becomes a SecretHandle the instant it is obtained.
- SecretHandle is safe to log, serialize, and embed in evidence: it exposes only
  an opaque handle id and a kind, never the value.
- There is no method that returns a raw secret. The vault can hash a handle's
  value (for redacted refs) but cannot reveal it.
- zeroize() overwrites and drops all stored material; call it in a finally block
  at run end.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretHandle:
    """An opaque reference to a secret held in the vault.

    __str__/__repr__ never reveal the underlying value. This object is what
    downstream evidence, journals, and results are allowed to see.
    """

    handle_id: str
    kind: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.handle_id

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"SecretHandle(kind={self.kind!r}, handle_id={self.handle_id!r})"


class SecretVault:
    def __init__(self) -> None:
        self._store: dict[str, bytearray] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def redact(self, secret: str | bytes | bytearray, kind: str) -> SecretHandle:
        """Store a secret and return a handle. This is the only ingress."""
        if isinstance(secret, str):
            raw = bytearray(secret.encode("utf-8"))
        elif isinstance(secret, (bytes, bytearray)):
            raw = bytearray(secret)
        else:
            raise TypeError("secret must be str, bytes, or bytearray")
        if not kind or not kind.replace("-", "").isalnum():
            raise ValueError("kind must be a short kebab/alnum label, e.g. 'pfx', 'nt-hash'")
        with self._lock:
            self._counter += 1
            handle_id = f"{kind}#redacted-{self._counter:02d}"
            self._store[handle_id] = raw
        return SecretHandle(handle_id=handle_id, kind=kind)

    def sha256_of(self, handle: SecretHandle) -> str:
        """Hash of the secret behind a handle. Safe for redactedRefs; not reversible."""
        raw = self._store.get(handle.handle_id)
        if raw is None:
            raise KeyError(f"unknown or zeroized handle: {handle.handle_id}")
        return hashlib.sha256(bytes(raw)).hexdigest()

    def handles(self) -> list[str]:
        with self._lock:
            return sorted(self._store.keys())

    def zeroize(self) -> None:
        """Overwrite and drop all stored material. Idempotent."""
        with self._lock:
            for raw in self._store.values():
                for i in range(len(raw)):
                    raw[i] = 0
            self._store.clear()

    def __enter__(self) -> SecretVault:  # noqa: PYI034  (Self needs 3.11; floor is 3.10)
        return self

    def __exit__(self, *exc) -> None:
        self.zeroize()
