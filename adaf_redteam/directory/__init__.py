"""Read-only Active Directory access for Phase 1 exposure capabilities.

Nothing in this package writes to the directory or requests Kerberos tickets. It
reads ACLs and specific attributes and normalizes them into an Ace list that the
capability analyzers reason over. The live LDAP collector is intentionally thin
and is marked lab_certified=False on its capabilities until a disposable-lab test
certifies it.
"""

from .acl import EXTENDED_RIGHTS, Ace, DirectorySource

__all__ = ["EXTENDED_RIGHTS", "Ace", "DirectorySource"]
