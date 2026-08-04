"""A fixture-backed DirectorySource.

Lets the full execute -> analyze -> bridge pipeline run offline against known ACE
data, for unit tests and for lab dry-runs before the live collector is certified.
Never touches a network.

Fixture JSON shape:
{
  "domain_acl":  [{"trustee": "...", "right": "...", "object_type": null, "effect": "Allow"}, ...],
  "object_acl":  [ ... same shape ... ],
  "gmsa_readers": ["S-1-5-..."]
}
"""

from __future__ import annotations

import json
from pathlib import Path

from .acl import Ace


def _to_aces(rows: list[dict]) -> list[Ace]:
    return [
        Ace(
            trustee=r["trustee"],
            right=r["right"],
            object_type=r.get("object_type"),
            effect=r.get("effect", "Allow"),
        )
        for r in rows
    ]


class FixtureDirectorySource:
    """Offline source implementing DirectorySource + the Kerberos/Netlogon probe
    methods, so every Phase 1 capability can run against a single fixture file.
    """

    def __init__(self, data: dict) -> None:
        self._domain_acl = _to_aces(data.get("domain_acl", []))
        self._object_acl = _to_aces(data.get("object_acl", []))
        self._gmsa_readers = list(data.get("gmsa_readers", []))
        self._asrep = dict(data.get("asrep", {}))
        self._tgs = dict(data.get("tgs", {}))
        self._zerologon = dict(data.get("zerologon", {}))
        # RBCD in-memory lab state: {target: {"current": <principal|None>,
        #   "s4u_ok": bool, "restore_fails": bool}}
        self._rbcd = {k: dict(v) for k, v in data.get("rbcd", {}).items()}
        # Shadow Credentials: {target: {"links": [...], "pkinit_ok": bool, "restore_fails": bool}}
        self._shadowcred = {k: dict(v) for k, v in data.get("shadowcred", {}).items()}
        self._sc_counter = 0
        # ESC1: {ca: {"issued": bool, "authenticated": bool, "revoke_ok": bool,
        #   "pfx": <str>, "serial": <str>}}
        self._esc1 = {k: dict(v) for k, v in data.get("esc1", {}).items()}
        # Phase 2 inc 3 fixtures (exec / forge / coercion / relay / evasion / reliability)
        self._exec = {k: dict(v) for k, v in data.get("exec", {}).items()}
        self._forge = {k: dict(v) for k, v in data.get("forge", {}).items()}
        self._coercion = {k: dict(v) for k, v in data.get("coercion", {}).items()}
        self._relay = {k: dict(v) for k, v in data.get("relay", {}).items()}
        self._evasion = {k: dict(v) for k, v in data.get("evasion", {}).items()}
        self._reliability = {k: dict(v) for k, v in data.get("reliability", {}).items()}
        # ESC6 (CA config-flag read) and ESC8 (coerced relay -> web enrollment).
        self._esc6 = {k: dict(v) for k, v in data.get("esc6", {}).items()}
        self._esc8 = {k: dict(v) for k, v in data.get("esc8", {}).items()}
        # Delegation: read side (msDS-AllowedToDelegateTo + UAC flags) and S4U proof.
        self._delegation = {k: dict(v) for k, v in data.get("delegation", {}).items()}
        self._s4u = {k: dict(v) for k, v in data.get("s4u", {}).items()}
        # NTDS/DPAPI read proof (bytes are fake fixture bytes; redacted by the capability).
        self._ntds = {k: dict(v) for k, v in data.get("ntds", {}).items()}
        # Discovery caps: privileged-group members, trusts, sIDHistory accounts,
        # ms-DS-MachineAccountQuota. Each is a plain LDAP read in production;
        # the fixture just serves canned dicts.
        self._group_members = {k: list(v) for k, v in data.get("group_members", {}).items()}
        self._trusts = {k: list(v) for k, v in data.get("trusts", {}).items()}
        self._sidhistory = {k: list(v) for k, v in data.get("sidhistory", {}).items()}
        self._mach_quota = dict(data.get("machine_account_quota", {}))

    @classmethod
    def from_file(cls, path: str | Path) -> FixtureDirectorySource:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    # DirectorySource
    def domain_acl(self, domain: str) -> list[Ace]:
        return self._domain_acl

    def object_acl(self, dn: str, *, attribute: str | None = None) -> list[Ace]:
        return self._object_acl

    def gmsa_readers(self, dn: str) -> list[str]:
        return self._gmsa_readers

    # KerberosProbe (metadata only; default = not exposed)
    def asrep(self, user: str) -> dict:
        return self._asrep.get(user, {"preauth_required": True})

    def tgs(self, spn: str) -> dict:
        return self._tgs.get(spn, {"obtained": False})

    # NetlogonProbe (detection only; default = patched)
    def zerologon_detect(self, dc: str, max_attempts: int = 2000) -> dict:
        return self._zerologon or {"accepted_zero_auth": False, "attempts_used": max_attempts}

    # RBCD mutation (in-memory; reversible so the restore path is exercisable)
    def read_rbcd(self, target: str):
        return self._rbcd.setdefault(target, {"current": None}).get("current")

    def write_rbcd(self, target: str, principal: str) -> None:
        self._rbcd.setdefault(target, {})["current"] = principal

    def verify_s4u(self, target: str, principal: str) -> bool:
        entry = self._rbcd.get(target, {})
        return bool(entry.get("s4u_ok")) and entry.get("current") == principal

    def clear_rbcd(self, target: str, *, restore_to) -> None:
        entry = self._rbcd.setdefault(target, {})
        # A fixture may simulate a failed restore to exercise the cleanup latch.
        if entry.get("restore_fails"):
            entry["current"] = "!!unrestored!!"
        else:
            entry["current"] = restore_to

    # Shadow Credentials mutation (reversible; private key is fake fixture bytes)
    def read_keycred(self, target: str) -> list:
        return list(self._shadowcred.setdefault(target, {}).setdefault("links", []))

    def add_keycred(self, target: str) -> dict:
        self._sc_counter += 1
        key_id = f"kc-{self._sc_counter}"
        self._shadowcred.setdefault(target, {}).setdefault("links", []).append(key_id)
        return {"key_id": key_id, "private_key": b"FIXTURE-FAKE-PRIVATE-KEY-BYTES"}

    def verify_pkinit(self, target: str) -> bool:
        return bool(self._shadowcred.get(target, {}).get("pkinit_ok"))

    def remove_keycred(self, target: str, key_id: str) -> None:
        entry = self._shadowcred.setdefault(target, {})
        if entry.get("restore_fails"):
            return  # leave the link in place to exercise the cleanup latch
        entry.setdefault("links", [])
        if key_id in entry["links"]:
            entry["links"].remove(key_id)

    # ESC1 enrollment (issuance is durable; revoke may be simulated to fail)
    def enroll(self, ca: str, *, requested_san: str) -> dict:
        e = self._esc1.get(ca, {})
        return {
            "issued": bool(e.get("issued", True)),
            "authenticated": bool(e.get("authenticated", True)),
            "pfx": e.get("pfx", "FIXTURE-FAKE-PFX-CONTENT"),
            "serial": e.get("serial", "1A2B3C4D8F2A"),
        }

    def revoke(self, ca: str, serial: str) -> bool:
        return bool(self._esc1.get(ca, {}).get("revoke_ok", True))

    # SVCCTL exec proof (benign marker; reversible service removal)
    def run_marker(self, target: str, marker: str) -> dict:
        e = self._exec.get(target, {})
        return {"marker_echoed": bool(e.get("marker_echoed", True)),
                "exit_code": int(e.get("exit_code", 0))}

    def remove_service(self, target: str) -> bool:
        return bool(self._exec.get(target, {}).get("service_removed", True))

    # Golden/silver ticket forgery (fake ticket bytes; redacted by the capability)
    def forge_and_auth(self, principal: str) -> dict:
        f = self._forge.get(principal, {})
        return {"auth_ok": bool(f.get("auth_ok", True)), "ticket": "FIXTURE-FAKE-TICKET-BYTES"}

    # Coercion (observation only)
    def trigger(self, target: str) -> dict:
        return {"callback_observed": bool(self._coercion.get(target, {}).get("callback_observed", True))}

    # SMB->LDAP relay to shadow cred (reversible)
    def coerce_and_relay(self, target: str) -> dict:
        r = self._relay.get(target, {})
        return {"relayed": bool(r.get("relayed", True)), "written": bool(r.get("written", True)),
                "privkey": "FIXTURE-FAKE-RELAY-KEY"}

    def remove_shadowcred(self, target: str) -> bool:
        return bool(self._relay.get(target, {}).get("restore_ok", True))

    # Adversary emulation / evasion + payload reliability (purple-team detection evidence)
    def emulate(self, target: str, technique: str) -> dict:
        return dict(self._evasion.get(target, {"detected": [], "not_detected": [technique], "controls": []}))

    def reliability(self, target: str, technique: str) -> dict:
        return dict(self._reliability.get(target, {"attempts": 1, "successes": 1, "detected": []}))

    # ESC6: CA edit-flags read (default: no vulnerable flag set)
    def ca_edit_flags(self, ca: str) -> list[str]:
        return list(self._esc6.get(ca, {}).get("flags", []))

    # ESC8: coerce + relay -> web enrollment (issuance is durable; revoke may fail)
    def esc8_relay(self, target: str) -> dict:
        e = self._esc8.get(target, {})
        return {
            "coerced": bool(e.get("coerced", True)),
            "relayed": bool(e.get("relayed", True)),
            "issued": bool(e.get("issued", True)),
            "authenticated": bool(e.get("authenticated", True)),
            "pfx": e.get("pfx", "FIXTURE-FAKE-PFX-CONTENT"),
            "serial": e.get("serial", "AABBCCDD1234"),
            "ca": e.get("ca", "http://ca01.corp.contoso.test/certsrv/"),
        }

    def esc8_revoke(self, ca: str, serial: str) -> bool:
        # Fixture keys by target (machine), so scan for a matching ca; default True.
        for entry in self._esc8.values():
            if entry.get("ca") == ca:
                return bool(entry.get("revoke_ok", True))
        return True

    # Delegation read (metadata only): default = no delegation configured
    def delegation_info(self, target: str) -> dict:
        return dict(self._delegation.get(target, {
            "unconstrained": False, "protocol_transition": False,
            "allowed_to_delegate_to": [],
        }))

    # S4U2Self/S4U2Proxy chain prover (boolean; no ticket bytes returned)
    def s4u_chain(self, source_principal: str, target_spn: str) -> dict:
        e = self._s4u.get(source_principal, {})
        return {
            "s4u2self_ok": bool(e.get("s4u2self_ok", True)),
            "s4u2proxy_ok": bool(e.get("s4u2proxy_ok", True)),
            "authenticated": bool(e.get("authenticated", True)),
        }

    # NTDS/DPAPI read proof (bytes are fake; the capability redacts through vault)
    def read_ntds_stream(self, target: str) -> dict:
        e = self._ntds.get(target, {})
        return {
            "readable": bool(e.get("ntds_readable", True)),
            "account_count": int(e.get("account_count", 0)),
            "sample": e.get("ntds_sample", "FIXTURE-FAKE-NTDS-SAMPLE-BYTES"),
        }

    def read_dpapi_backup_key(self, target: str) -> dict:
        e = self._ntds.get(target, {})
        return {
            "readable": bool(e.get("dpapi_readable", True)),
            "key_bytes": e.get("dpapi_key", "FIXTURE-FAKE-DPAPI-BACKUP-KEY"),
        }

    # Discovery: privileged-group membership (recursive expansion is opaque here)
    def group_members(self, group_dn: str, *, recursive: bool = True) -> list[dict]:
        return list(self._group_members.get(group_dn, []))

    # Discovery: trust inventory
    def list_trusts(self, domain: str) -> list[dict]:
        return list(self._trusts.get(domain, []))

    # Discovery: sIDHistory accounts
    def accounts_with_sidhistory(self, domain: str) -> list[dict]:
        return list(self._sidhistory.get(domain, []))

    # Discovery: ms-DS-MachineAccountQuota
    def machine_account_quota(self, domain: str) -> int:
        # Default of 10 mirrors the AD default when the attribute is absent.
        return int(self._mach_quota.get(domain, 10))
