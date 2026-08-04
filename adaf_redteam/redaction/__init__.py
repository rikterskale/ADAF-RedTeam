"""The single choke point between raw secrets and everything else.

Nothing outside this package should ever hold a raw secret. Capabilities obtain a
secret, immediately call SecretVault.redact(), and work with the returned handle.
The vault is in-memory only, is never serialized, and is zeroized at run end.
"""

from .vault import SecretHandle, SecretVault

__all__ = ["SecretHandle", "SecretVault"]
