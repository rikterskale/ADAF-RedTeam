"""Netlogon / Zerologon capabilities.

- ZerologonDetectionCapability: SAFE. Detects vulnerability without ever calling
  NetrServerPasswordSet2; the machine account is never modified.
- ZerologonResetCapability: the destructive exploit (resets the DC machine-account
  password). Lab-only, containment-gated, reset-then-restore, cleanup-latched. Its
  destructive primitive is intentionally NOT implemented in this repo.
"""

from .zerologon import ZerologonDetectionCapability, ZerologonResetCapability

__all__ = ["ZerologonDetectionCapability", "ZerologonResetCapability"]
