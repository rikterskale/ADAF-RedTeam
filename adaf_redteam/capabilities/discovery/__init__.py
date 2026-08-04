"""Discovery / inventory capabilities.

Read-only Executable capabilities that enumerate directory state used by
attack-path analysis. Each is metadata-only and never touches secret material —
the outputs are ACLs, group memberships, trust relationships, SIDHistory
values, and domain attributes. None mutate; all are safe to run against
production under normal engagement authorization.
"""

from .acl_write_rights import AclWriteRightsCapability
from .machine_account_quota import MachineAccountQuotaCapability
from .privileged_group_membership import PrivilegedGroupMembershipCapability
from .sidhistory import SidHistoryInventoryCapability
from .trust_inventory import TrustInventoryCapability

__all__ = [
    "AclWriteRightsCapability",
    "MachineAccountQuotaCapability",
    "PrivilegedGroupMembershipCapability",
    "SidHistoryInventoryCapability",
    "TrustInventoryCapability",
]
