"""Privileged group membership inventory (Executable, secret-free).

Enumerates direct AND transitive members of a named privileged group (Domain
Admins, Enterprise Admins, Schema Admins, Account/Backup/Server/Print
Operators, DNSAdmins, or any group the caller names as the target). The live
collector uses LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941) so a
single query returns transitive membership; nested groups do not hide members.

Read-only: enumerates members, does not add/remove/modify. The result is a
sorted list of member DNs plus counts split into users / computers / groups.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


def analyze(group_dn: str, members: list[dict]) -> CapabilityResult:
    """`members` is a list of {dn, class} dicts (`class` = user/computer/group)."""
    users = sorted(m["dn"] for m in members if m.get("class") == "user")
    computers = sorted(m["dn"] for m in members if m.get("class") == "computer")
    groups = sorted(m["dn"] for m in members if m.get("class") == "group")
    total = len(users) + len(computers) + len(groups)
    return CapabilityResult(
        # A privileged group with zero members would be a suspicious finding
        # too, but the operationally interesting case is "who is privileged?".
        verdict="Confirmed" if total > 0 else "NotExploitable",
        proof_class="privileged-group-members-enumerated" if total > 0
        else "privileged-group-empty",
        assertions=[
            (f"Group has {total} transitive member(s): "
             f"{len(users)} user(s), {len(computers)} computer(s), "
             f"{len(groups)} nested group(s)."),
            "Read-only enumeration: no add-member, no remove-member, no membership change.",
        ],
        redacted_refs={
            "group": group_dn,
            "memberCountTotal": total,
            "memberCountUsers": len(users),
            "memberCountComputers": len(computers),
            "memberCountNestedGroups": len(groups),
            "memberUsers": users,
            "memberComputers": computers,
            "memberNestedGroups": groups,
        },
    )


class PrivilegedGroupMembershipCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "privileged-group-inventory",
            "reads": ("member attribute of the target group, expanded transitively "
                      "via LDAP_MATCHING_RULE_IN_CHAIN"),
            "does_not": ["add or remove members", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        members = source.group_members(self.action.target, recursive=True)
        return analyze(self.action.target, members)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)
