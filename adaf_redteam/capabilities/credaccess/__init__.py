"""Credential-access exposure capabilities.

Phase 1 caps (DCSync/gMSA/LAPS) prove *authorization exposure* — who could
retrieve, without ever performing the retrieval. NtdsDpapiReadProofCapability is
the exception: it proves the operator's session CAN read NTDS.dit and the domain
DPAPI backup key, but streams the bytes into vault handles and discards them —
no file is written or exported.
"""

from .dcsync_rights import DcsyncRightsCapability
from .gmsa_read import GmsaReadCapability
from .laps_read import LapsReadCapability
from .ntds_dpapi import NtdsDpapiReadProofCapability

__all__ = [
    "DcsyncRightsCapability",
    "GmsaReadCapability",
    "LapsReadCapability",
    "NtdsDpapiReadProofCapability",
]
