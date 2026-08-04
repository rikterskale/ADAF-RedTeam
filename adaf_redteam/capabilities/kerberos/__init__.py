"""Kerberos exposure capabilities.

Metadata proofs (AS-REP roasting, Kerberoasting, delegation-rights) never return
or export the crackable AS-REP / TGS / ticket. State-changing capabilities
(shadow-cred, RBCD, golden/silver, S4U proof) confine secret material to vault
handles and either fully restore or report durable residue honestly.
"""

from .asrep_roast import AsrepRoastCapability
from .delegation_rights import DelegationRightsCapability
from .delegation_s4u import DelegationS4uProofCapability
from .golden_silver import GoldenSilverTicketCapability
from .kerberoast import KerberoastCapability
from .rbcd_write import RbcdWriteCapability
from .shadowcred_write import ShadowCredWriteCapability

__all__ = [
    "AsrepRoastCapability",
    "DelegationRightsCapability",
    "DelegationS4uProofCapability",
    "GoldenSilverTicketCapability",
    "KerberoastCapability",
    "RbcdWriteCapability",
    "ShadowCredWriteCapability",
]
