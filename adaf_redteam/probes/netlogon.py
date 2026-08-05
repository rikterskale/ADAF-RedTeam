"""Live Netlogon probe for SAFE Zerologon detection.

Detection only: attempts ComputeNetlogonCredential with a zero client
challenge a bounded number of times and observes whether the DC accepts it.
It STOPS before NetrServerPasswordSet2 — it never calls the password-set
operation, so it cannot modify the machine account. The destructive reset lives
only in the separate zerologon-reset capability (whose primitive is intentionally
not implemented).

The live path ships lab_certified=False; results are stamped UNVALIDATED until
a disposable-lab certification test promotes the capability.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def _require_deps():
    try:
        import impacket  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "live Netlogon probe needs the 'kerberos' extra (impacket): pip install -e '.[kerberos]'"
        ) from exc


class LiveNetlogonProbe:
    def __init__(self, dc: str) -> None:
        _require_deps()
        if not dc:
            raise ValueError("dc hostname/IP is required")
        self._dc = dc

    def zerologon_detect(self, dc: str | None = None, max_attempts: int = 2000) -> dict:
        """Bounded zero-challenge Netlogon auth attempts. Detection only.

        Returns:
            {"accepted_zero_auth": bool, "attempts_used": int}

        Bounds:
          - at most `max_attempts` authenticate attempts (default 2000)
          - never calls NetrServerPasswordSet2 / NetrServerPasswordSet
          - never modifies any machine-account password
        """
        _require_deps()
        from impacket.dcerpc.v5 import nrpc, epm, transport
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        target = dc or self._dc
        # Strip trailing $ from machine account names if an operator passes one.
        server_name = target.rstrip("$").split(".")[0].upper()
        max_attempts = max(1, min(int(max_attempts), 5000))

        # Bind to the Netlogon RPC interface via the endpoint mapper.
        string_binding = epm.hept_map(target, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        attempts_used = 0
        accepted = False
        try:
            for attempt in range(1, max_attempts + 1):
                attempts_used = attempt
                # Zero client challenge — the entire detection signal.
                plaintext = b"\x00" * 8
                ciphertext = b"\x00" * 8
                try:
                    nrpc.hNetrServerReqChallenge(dce, NULL, server_name + "\x00", plaintext)
                    server_auth = nrpc.hNetrServerAuthenticate3(
                        dce,
                        NULL,
                        server_name + "$\x00",
                        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                        server_name + "\x00",
                        ciphertext,
                        0,
                    )
                    # If authenticate succeeded without raising, the DC accepted
                    # a zero credential — vulnerable.
                    _ = server_auth  # keep the response local; never return it
                    accepted = True
                    break
                except nrpc.DCERPCSessionError as exc:
                    # STATUS_ACCESS_DENIED (0xc0000022) is the patched/normal path.
                    # Any other unexpected error is re-raised after the loop bound.
                    if exc.error_code == 0xc0000022:
                        continue
                    raise RuntimeError(
                        f"Netlogon authenticate failed unexpectedly on attempt "
                        f"{attempt}: {exc}"
                    ) from exc
                except DCERPCException as exc:
                    # Bind/transport failures should surface, not be mapped to "patched".
                    raise RuntimeError(f"Netlogon RPC failure: {exc}") from exc
        finally:
            try:
                dce.disconnect()
            except Exception:  # pragma: no cover - best-effort cleanup
                pass

        # Explicit non-goals encoded in the return shape: no password-set call
        # was made, no machine-account bytes were touched.
        return {
            "accepted_zero_auth": accepted,
            "attempts_used": attempts_used,
        }
