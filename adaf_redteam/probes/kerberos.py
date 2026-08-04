"""Live Kerberos probes.

`LiveKerberosProbe.asrep` is the implemented, offline-tested primitive for
`asrep-roast-validation`. It sends one padata-free AS-REQ for the target user
and returns only the metadata the analyzer needs (whether pre-authentication
was required and, if not, the encryption type of the AS-REP). The AS-REP's
encrypted blob (`enc-part.cipher`) — the crackable material — is NEVER read,
returned, logged, or written. Bounded to the capability's `plan()`: exactly one
AS-REQ per call, no padata, no post-processing.

The Kerberoast / TGS metadata probe and the S4U2Self/S4U2Proxy delegation
prover are still lab-certification boundaries and raise; their orchestration
is exercised offline via `--fixture`.

LDAPS is used for LdapDirectorySource; Kerberos AS traffic is UDP/TCP 88 to the
KDC. The KDC hostname defaults to the domain (Windows KDCs typically answer on
the domain SRV record); it can be overridden with `dc=` at construction.
"""

from __future__ import annotations

import datetime
import random


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live Kerberos probe needs the 'kerberos' extra: pip install -e '.[kerberos]'"
        ) from exc


# Etype IDs mirrored from adaf_redteam/probes/__init__.py so this module can be
# read on its own. RC4 is the crackable case operationally.
_ETYPE_AES256 = 18
_ETYPE_AES128 = 17
_ETYPE_RC4 = 23


def build_asrep_probe_request(user: str, domain: str, *, nonce: int | None = None) -> bytes:
    """Build a padata-free AS-REQ for `user@domain` (bytes ready to send).

    Broken out from `asrep()` so offline tests can round-trip the request
    without touching the network. No secrets are involved in constructing it —
    an AS-REQ is public information.
    """
    _require_deps()
    # Imports are inside the function so the module loads without impacket if
    # a user only wants the request builder's docstring for reference.
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der.encoder import encode as der_encode

    if not user or not domain:
        raise ValueError("user and domain are required")
    realm = domain.upper()

    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    # Deliberately no padata — the whole point of this probe is to observe
    # whether the KDC insists on PA_ENC_TIMESTAMP (normal) or returns an AS-REP
    # outright (DONT_REQUIRE_PREAUTH account).

    req_body = seq_set(as_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ])
    cname = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(req_body, "cname", cname.components_to_asn1)
    req_body["realm"] = realm
    sname = Principal(f"krbtgt/{realm}",
                      type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(req_body, "sname", sname.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    req_body["till"] = KerberosTime.to_asn1(now)
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = int(nonce if nonce is not None else random.getrandbits(31))

    # Advertise strong ciphers first so an RC4 AS-REP from a modern KDC is a
    # deliberate signal (the account is stored with an RC4-only key, i.e. a
    # weak/legacy configuration), not an artifact of our ordering.
    seq_set_iter(req_body, "etype", (_ETYPE_AES256, _ETYPE_AES128, _ETYPE_RC4))
    return der_encode(as_req)


def extract_asrep_metadata(response_bytes: bytes) -> dict:
    """Parse an AS-REP wire response into metadata-only. Never touches cipher.

    The `enc-part.cipher` field of an AS-REP is the crackable material. This
    function deliberately reads only `enc-part.etype` — nothing else about the
    AS-REP body is inspected, so the crackable bytes cannot leak through the
    return value.
    """
    _require_deps()
    from impacket.krb5.asn1 import AS_REP
    from pyasn1.codec.der.decoder import decode as der_decode

    as_rep, _ = der_decode(response_bytes, asn1Spec=AS_REP())
    return {"preauth_required": False, "etype": int(as_rep["enc-part"]["etype"])}


class LiveKerberosProbe:
    def __init__(self, domain: str, *, dc: str | None = None) -> None:
        _require_deps()
        if not domain:
            raise ValueError("domain is required")
        self._domain = domain
        self._dc = dc

    def asrep(self, user: str) -> dict:
        """Send one padata-free AS-REQ and return {preauth_required, etype}.

        Bounded to plan(): one AS-REQ, no retries, no additional padata, no
        post-processing of the AS-REP body beyond reading `enc-part.etype`.
        The AS-REP's encrypted blob is never read.
        """
        from impacket.krb5 import constants
        from impacket.krb5.kerberosv5 import KerberosError, sendReceive

        data = build_asrep_probe_request(user, self._domain)
        kdc = self._dc or self._domain
        try:
            # sendReceive returns raw AS-REP bytes on success; raises
            # KerberosError on KRB_ERROR (including KDC_ERR_PREAUTH_REQUIRED).
            response = sendReceive(data, self._domain.upper(), kdc)
        except KerberosError as exc:
            code = exc.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                # The normal case: account requires preauth -> not roastable.
                return {"preauth_required": True, "etype": None}
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                raise RuntimeError(
                    f"KDC reports the client principal {user!r} is unknown; "
                    "confirm the target exists in the authorized domain."
                ) from exc
            # Anything else (e.g. clock skew, encryption type not supported) is
            # a live-run failure the operator needs to see, not silently mapped
            # to "not roastable".
            raise RuntimeError(f"AS-REQ failed: {exc}") from exc
        return extract_asrep_metadata(response)

    def tgs(self, spn: str) -> dict:  # pragma: no cover - live I/O
        raise NotImplementedError(
            "TGS metadata probe is not lab-certified. Implement a bounded TGS-REQ, record "
            "obtained + etype, and DISCARD the ticket blob."
        )


class LiveDelegationProver:
    """S4U2Self + S4U2Proxy chain prover. Boolean-only. Not lab-certified."""

    def __init__(self, domain: str) -> None:
        _require_deps()
        self._domain = domain

    def s4u_chain(self, source_principal: str, target_spn: str) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "S4U2Self/S4U2Proxy chain prover is intentionally not implemented (lab boundary). "
            "The certified implementation MUST report booleans only and DISCARD both the "
            "S4U2Self and S4U2Proxy tickets — no ticket bytes may be returned or exported."
        )
