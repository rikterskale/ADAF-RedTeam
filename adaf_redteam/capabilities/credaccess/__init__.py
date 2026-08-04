"""Credential-access exposure capabilities (Phase 1, read/metadata only).

These prove *authorization exposure* — who could DCSync, read a gMSA password, or
read a LAPS password — without ever performing the replication or reading the
secret value. No secret material is touched, so nothing needs redaction.
"""

from .dcsync_rights import DcsyncRightsCapability
from .gmsa_read import GmsaReadCapability
from .laps_read import LapsReadCapability

__all__ = ["DcsyncRightsCapability", "GmsaReadCapability", "LapsReadCapability"]
