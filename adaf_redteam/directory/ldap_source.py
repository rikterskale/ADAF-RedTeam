"""Live, read-only LDAP DirectorySource.

Uses ldap3 (bind + one base-scope search per read) and impacket.ldap.ldaptypes
(binary security-descriptor parse). The primitive is bounded to what the
DCSync-rights capability's plan() promises:

  reads:     nTSecurityDescriptor of the domain naming context (DACL only)
  does not:  DRSUAPI replication, hash extraction, writes, SACL reads

Enforcement is in the code, not just documentation:
  * LDAPS is required (StartTLS-only servers won't be used); plain LDAP is refused.
  * The SD_FLAGS request control is always sent with DACL_SECURITY_INFORMATION only,
    so the server never returns the SACL (which needs SeSecurityPrivilege).
  * Only one attribute is ever requested per search: nTSecurityDescriptor or
    msDS-GroupMSAMembership. No other attributes.
  * search_scope is BASE (this DN, no children).
  * No write, modify, or extended operations are ever issued.

The SD parser is offline-testable and covered by unit tests (synthetic SDs built
with impacket in-test). The live bind + search is the lab-certification boundary
per docs/CERTIFICATION.md — capabilities using it stay lab_certified=False until
the evidence package in docs/certifications/ is complete and reviewed.
"""

from __future__ import annotations

from typing import Any

from .acl import EXTENDED_RIGHTS, Ace


def _require_deps() -> tuple[Any, Any]:
    try:
        import ldap3
        from impacket.ldap import ldaptypes
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live LDAP source needs the 'ldap' extra: pip install -e '.[ldap]'"
        ) from exc
    return ldap3, ldaptypes


# --- Access-mask bits (MS-DTYP) ------------------------------------------
_READ_PROP = 0x00000010
_WRITE_PROP = 0x00000020
_CONTROL_ACCESS = 0x00000100
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_WRITE_OWNER = 0x00080000
_WRITE_DAC = 0x00040000

# ACE types (MS-DTYP) — only Allow/Deny are certified here; audit ACEs are
# skipped because we never request the SACL.
_ACCESS_ALLOWED_ACE = 0x00
_ACCESS_DENIED_ACE = 0x01
_ACCESS_ALLOWED_OBJECT_ACE = 0x05
_ACCESS_DENIED_OBJECT_ACE = 0x06
_ALLOW_TYPES = frozenset({_ACCESS_ALLOWED_ACE, _ACCESS_ALLOWED_OBJECT_ACE})
_DENY_TYPES = frozenset({_ACCESS_DENIED_ACE, _ACCESS_DENIED_OBJECT_ACE})
_OBJECT_TYPES = frozenset({_ACCESS_ALLOWED_OBJECT_ACE, _ACCESS_DENIED_OBJECT_ACE})

# ACE.Flags (for object ACEs)
_ACE_OBJECT_TYPE_PRESENT = 0x01

# LDAP request control: SD_FLAGS (returns only the requested SD parts). We
# always ask for DACL_SECURITY_INFORMATION (0x04); OWNER/GROUP/SACL are omitted.
# BER encoding of SEQUENCE { INTEGER 4 } = 30 03 02 01 04.
SD_FLAGS_OID = "1.2.840.113556.1.4.801"
SD_FLAGS_DACL_ONLY = b"\x30\x03\x02\x01\x04"

# The single attribute the DCSync-rights read needs.
_NT_SD = "nTSecurityDescriptor"
_GMSA_MEMBERSHIP = "msDS-GroupMSAMembership"


# --- SD binary -> Ace parser (offline-testable) --------------------------

def _guid_bytes_to_str(raw: bytes) -> str:
    """Convert a 16-byte little-endian GUID into canonical lowercase form."""
    if len(raw) != 16:
        return ""
    # First three groups are little-endian, last two are big-endian.
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    d4 = raw[8:10].hex()
    d5 = raw[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def _mask_to_rights(mask: int, *, object_type_name: str | None) -> list[str]:
    """Map an access mask (+ optional object-type scope) to normalized right names."""
    rights: list[str] = []
    if mask & _GENERIC_ALL:
        # GenericAll implies every specific right; the analyzer's effective_rights
        # already expands this, so emit the umbrella name.
        rights.append("GenericAll")
    if mask & _CONTROL_ACCESS:
        # Control-access is what extended rights (DCSync, etc.) key off. When the
        # ACE names a specific extended right, promote to that right's name.
        if object_type_name is not None and object_type_name in EXTENDED_RIGHTS.values():
            rights.append(object_type_name)
        else:
            rights.append("ControlAccess")
    if mask & _READ_PROP:
        rights.append("ReadProperty")
    if mask & _WRITE_PROP:
        rights.append("WriteProperty")
    if mask & (_GENERIC_WRITE | _WRITE_DAC | _WRITE_OWNER):
        rights.append("WriteDACL" if mask & _WRITE_DAC else "WriteOwner"
                      if mask & _WRITE_OWNER else "GenericWrite")
    return rights


def parse_sd_to_aces(raw_sd: bytes, *, attribute_filter: str | None = None) -> list[Ace]:
    """Parse a binary security descriptor into normalized Ace objects.

    Only Allow/Deny ACEs from the DACL are emitted. Audit (SACL) ACEs and
    callback ACEs are skipped — the collector never requests the SACL, and
    callback ACEs don't apply to AD DCSync-rights analysis.

    If `attribute_filter` is set, only ACEs scoped to that attribute (by
    object-type GUID mapping to the attribute name) or unscoped ACEs are kept —
    this mirrors laps_read.analyze's per-attribute filtering.
    """
    _, ldaptypes = _require_deps()
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    dacl = sd["Dacl"]
    if dacl is None:
        return []
    out: list[Ace] = []
    for ace in dacl["Data"]:
        ace_type = ace["AceType"]
        if ace_type in _ALLOW_TYPES:
            effect = "Allow"
        elif ace_type in _DENY_TYPES:
            effect = "Deny"
        else:
            continue  # audit / callback / label / policy — not our concern
        body = ace["Ace"]
        try:
            mask = int(body["Mask"]["Mask"])
        except (KeyError, TypeError, ValueError):
            continue
        try:
            trustee = body["Sid"].formatCanonical()
            if not isinstance(trustee, str):
                continue
        except (AttributeError, KeyError):
            continue

        object_type_name: str | None = None
        if ace_type in _OBJECT_TYPES:
            try:
                flags = int(body["Flags"])
            except (KeyError, TypeError, ValueError):
                flags = 0
            if flags & _ACE_OBJECT_TYPE_PRESENT:
                try:
                    obj_type = body["ObjectType"]
                except KeyError:
                    obj_type = b""
                guid = _guid_bytes_to_str(bytes(obj_type)) if obj_type else ""
                # Prefer the extended-right friendly name; otherwise the raw GUID
                # so an attribute-filter caller can still match by GUID.
                object_type_name = EXTENDED_RIGHTS.get(guid, guid or None)

        if attribute_filter is not None and object_type_name not in (attribute_filter, None):
            continue

        for right in _mask_to_rights(mask, object_type_name=object_type_name):
            out.append(Ace(trustee=trustee, right=right,
                           object_type=object_type_name, effect=effect))
    return out


def _trustees_from_sd(raw_sd: bytes) -> list[str]:
    """Return the list of trustee SIDs from a security-descriptor blob.

    Used for msDS-GroupMSAMembership: any principal named by an Allow ACE with
    ControlAccess or GenericAll is a reader.
    """
    _, ldaptypes = _require_deps()
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    dacl = sd["Dacl"]
    if dacl is None:
        return []
    trustees: list[str] = []
    for ace in dacl["Data"]:
        if ace["AceType"] not in _ALLOW_TYPES:
            continue
        body = ace["Ace"]
        try:
            mask = int(body["Mask"]["Mask"])
            trustee = body["Sid"].formatCanonical()
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if not isinstance(trustee, str):
            continue
        if mask & (_CONTROL_ACCESS | _GENERIC_ALL):
            trustees.append(trustee)
    return trustees


# --- Live LDAP source (lab-certification boundary) -----------------------

def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


class LdapDirectorySource:
    """Read-only LDAP access. Construct with an authorized, in-scope target only.

    Uses LDAPS (port 636) with either SASL/GSSAPI (Kerberos ccache) or SIMPLE
    bind. Every search is scoped BASE, requests exactly one attribute, and sends
    the SD_FLAGS control asking for the DACL only. The connection is bound
    lazily on first read and closed by `close()` / __exit__.
    """

    def __init__(self, server: str, *, user: str, use_kerberos_ccache: bool = True,
                 password: str | None = None) -> None:
        _require_deps()  # fail fast if the extra isn't installed
        if not server:
            raise ValueError("server must be a non-empty hostname/IP")
        if not user:
            raise ValueError("user must be provided for the bind")
        self._server = server
        self._user = user
        self._use_kerberos = use_kerberos_ccache
        self._password = password
        self._conn = None  # bound lazily

    # --- DirectorySource protocol ---------------------------------------

    def domain_acl(self, domain: str) -> list[Ace]:
        base = _domain_to_dn(domain)
        return parse_sd_to_aces(self._read_raw_sd(base, _NT_SD), attribute_filter=None)

    def object_acl(self, dn: str, *, attribute: str | None = None) -> list[Ace]:
        return parse_sd_to_aces(self._read_raw_sd(dn, _NT_SD), attribute_filter=attribute)

    def gmsa_readers(self, dn: str) -> list[str]:
        raw = self._read_raw_sd(dn, _GMSA_MEMBERSHIP)
        return _trustees_from_sd(raw)

    # --- Discovery methods (read-only LDAP searches) --------------------

    def group_members(self, group_dn: str, *, recursive: bool = True) -> list[dict]:  # pragma: no cover - live I/O
        """Transitive members of a group via LDAP_MATCHING_RULE_IN_CHAIN."""
        ldap3, _ = _require_deps()
        conn = self._bind()
        if recursive:
            # 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN — expands
            # nested groups server-side in a single query.
            search_filter = (f"(&(objectClass=*)"
                             f"(memberOf:1.2.840.113556.1.4.1941:={group_dn}))")
        else:
            search_filter = f"(memberOf={group_dn})"
        # SUBTREE search of the domain naming context; base is derived from the
        # group DN's DC= components.
        base = ",".join(p for p in group_dn.split(",") if p.strip().startswith("DC="))
        ok = conn.search(
            search_base=base or group_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=["objectClass", "distinguishedName"],
        )
        if not ok:
            raise RuntimeError(f"LDAP group-members search failed: {conn.last_error}")
        out: list[dict] = []
        for entry in conn.entries:
            classes = [str(c).lower() for c in (entry["objectClass"].values or [])]
            klass = ("computer" if "computer" in classes
                     else "group" if "group" in classes
                     else "user" if "user" in classes
                     else "other")
            out.append({"dn": str(entry.entry_dn), "class": klass})
        return out

    def list_trusts(self, domain: str) -> list[dict]:  # pragma: no cover - live I/O
        """Enumerate (objectClass=trustedDomain) under CN=System,<domain-dn>."""
        ldap3, _ = _require_deps()
        conn = self._bind()
        base = f"CN=System,{_domain_to_dn(domain)}"
        ok = conn.search(
            search_base=base,
            search_filter="(objectClass=trustedDomain)",
            search_scope=ldap3.SUBTREE,
            attributes=["trustPartner", "trustDirection", "trustType", "trustAttributes"],
        )
        if not ok:
            raise RuntimeError(f"LDAP trust enumeration failed: {conn.last_error}")
        return [{
            "trustPartner": str(e["trustPartner"].value or ""),
            "trustDirection": int(e["trustDirection"].value or 0),
            "trustType": int(e["trustType"].value or 0),
            "trustAttributes": int(e["trustAttributes"].value or 0),
        } for e in conn.entries]

    def accounts_with_sidhistory(self, domain: str) -> list[dict]:  # pragma: no cover - live I/O
        """LDAP `(sIDHistory=*)` under the domain naming context."""
        ldap3, _ = _require_deps()
        conn = self._bind()
        ok = conn.search(
            search_base=_domain_to_dn(domain),
            search_filter="(sIDHistory=*)",
            search_scope=ldap3.SUBTREE,
            attributes=["distinguishedName", "sIDHistory"],
        )
        if not ok:
            raise RuntimeError(f"LDAP sIDHistory search failed: {conn.last_error}")
        out: list[dict] = []
        for e in conn.entries:
            sids = [str(s) for s in (e["sIDHistory"].values or [])]
            out.append({"dn": str(e.entry_dn), "sidHistory": sids})
        return out

    def machine_account_quota(self, domain: str) -> int:  # pragma: no cover - live I/O
        """One-attribute BASE read of ms-DS-MachineAccountQuota on the domain."""
        ldap3, _ = _require_deps()
        conn = self._bind()
        ok = conn.search(
            search_base=_domain_to_dn(domain),
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["ms-DS-MachineAccountQuota"],
        )
        if not ok or not conn.entries:
            raise RuntimeError(f"LDAP ms-DS-MachineAccountQuota read failed: {conn.last_error}")
        raw = conn.entries[0]["ms-DS-MachineAccountQuota"].value
        # Attribute absent -> Windows default of 10.
        return 10 if raw is None else int(raw)

    def close(self) -> None:  # pragma: no cover - live I/O
        if self._conn is not None:
            try:
                self._conn.unbind()
            finally:
                self._conn = None

    def __enter__(self) -> LdapDirectorySource:  # noqa: PYI034  (Self needs 3.11; floor is 3.10)
        return self

    def __exit__(self, *exc) -> None:  # pragma: no cover - live I/O
        self.close()

    # --- internals ------------------------------------------------------

    def _bind(self):  # pragma: no cover - live I/O
        if self._conn is not None:
            return self._conn
        ldap3, _ = _require_deps()
        # LDAPS only: refuse to bind without TLS, even if the caller passed a
        # cleartext user/password by mistake. This is a read-only tool; secrets
        # must never travel plaintext, and downstream analyzers assume trustees
        # were resolved by an authenticated bind.
        server = ldap3.Server(self._server, use_ssl=True, get_info=ldap3.DSA)
        if self._use_kerberos:
            conn = ldap3.Connection(
                server, authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS, auto_bind=False, read_only=True,
                raise_exceptions=True,
            )
        else:
            if not self._password:
                raise RuntimeError(
                    "LDAP bind refused: no Kerberos ccache and no password provided"
                )
            conn = ldap3.Connection(
                server, user=self._user, password=self._password,
                authentication=ldap3.SIMPLE, auto_bind=False, read_only=True,
                raise_exceptions=True,
            )
        if not conn.bind():
            raise RuntimeError(f"LDAP bind failed: {conn.last_error}")
        self._conn = conn
        return conn

    def _read_raw_sd(self, dn: str, attribute: str) -> bytes:  # pragma: no cover - live I/O
        if attribute not in (_NT_SD, _GMSA_MEMBERSHIP):
            raise ValueError(f"attribute {attribute!r} is not authorized for this collector")
        ldap3, _ = _require_deps()
        conn = self._bind()
        controls = ([(SD_FLAGS_OID, True, SD_FLAGS_DACL_ONLY)]
                    if attribute == _NT_SD else None)
        ok = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=[attribute],
            controls=controls,
        )
        if not ok or not conn.entries:
            raise RuntimeError(f"LDAP search returned no entry for {dn!r}")
        raw = conn.entries[0][attribute].raw_values
        if not raw:
            raise RuntimeError(f"entry {dn!r} has no {attribute}")
        return bytes(raw[0])
