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
