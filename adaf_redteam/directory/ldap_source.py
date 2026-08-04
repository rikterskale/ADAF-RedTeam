"""Live, read-only LDAP DirectorySource.

UNVALIDATED against a live DC in this build. Capabilities using it ship
lab_certified=False; the CLI flags results as unvalidated until a disposable-lab
test certifies this collector. It performs only LDAP search operations — no
writes, no Kerberos ticket requests, no secret attributes are returned.

Dependencies are optional (the `ldap` extra). Importing this module does not pull
them in; they are required only when a live source is actually constructed.
"""

from __future__ import annotations

from .acl import Ace


def _require_deps():
    try:
        import ldap3  # noqa: F401
        from impacket.ldap import ldaptypes  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live LDAP source needs the 'ldap' extra: pip install -e '.[ldap]'"
        ) from exc


# Access-mask bits we care about (subset).
_ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
_ADS_RIGHT_DS_READ_PROP = 0x00000010
_ADS_RIGHT_GENERIC_ALL = 0x10000000


class LdapDirectorySource:
    """Read-only LDAP access. Construct with an authorized, in-scope target only."""

    def __init__(self, server: str, *, user: str, use_kerberos_ccache: bool = True,
                 password: str | None = None, use_ssl: bool = True) -> None:
        _require_deps()
        self._server = server
        self._user = user
        self._use_kerberos = use_kerberos_ccache
        self._password = password
        self._use_ssl = use_ssl
        self._conn = None  # bound lazily

    # --- DirectorySource protocol ---------------------------------------

    def domain_acl(self, domain: str) -> list[Ace]:
        base = _domain_to_dn(domain)
        return self._read_sd_aces(base, attribute=None)

    def object_acl(self, dn: str, *, attribute: str | None = None) -> list[Ace]:
        return self._read_sd_aces(dn, attribute=attribute)

    def gmsa_readers(self, dn: str) -> list[str]:
        sd = self._read_raw_sd(dn, "msDS-GroupMSAMembership")
        return _trustees_from_sd(sd)

    # --- internals (thin; certified in lab) -----------------------------

    def _read_raw_sd(self, dn: str, attribute: str) -> bytes:  # pragma: no cover - live I/O
        raise NotImplementedError(
            "LdapDirectorySource live read is not lab-certified in this build. "
            "Wire ldap3 bind + nTSecurityDescriptor read here behind a disposable-lab gate."
        )

    def _read_sd_aces(self, dn: str, *, attribute: str | None) -> list[Ace]:  # pragma: no cover
        raw = self._read_raw_sd(dn, "nTSecurityDescriptor")
        return list(parse_sd_to_aces(raw, attribute_filter=attribute))


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def parse_sd_to_aces(raw_sd: bytes, *, attribute_filter: str | None = None) -> list[Ace]:  # pragma: no cover
    """Parse a binary security descriptor into normalized Ace objects.

    Left as the lab-certified boundary: implement with impacket ldaptypes
    (SR_SECURITY_DESCRIPTOR -> ACL -> ACE), mapping access masks and object-type
    GUIDs (via EXTENDED_RIGHTS) to normalized right names. Analyzers are tested
    against the Ace model directly, so this parser is the only uncertified piece.
    """
    raise NotImplementedError("SD parsing is the lab-certification boundary; see analyzers' tests")


def _trustees_from_sd(raw_sd: bytes) -> list[str]:  # pragma: no cover
    raise NotImplementedError("gMSA membership SD parsing is the lab-certification boundary")
