"""Live protocol probes for Kerberos, Netlogon, ADCS, RBCD, ShadowCred, coercion,
relay, credential-access, execution, forgery, and emulation.

Every probe is the lab-certification boundary for its capability. Most methods
raise NotImplementedError today; the Kerberos AS-REP/TGS probes are implemented
and offline-tested but still ship lab_certified=False, so the CLI stamps their
results UNVALIDATED until a disposable-lab certification test promotes them.
Analyzers are
unit-tested; the live probe is the certification boundary. Use --fixture to run
the pipeline offline.
"""

# Kerberos encryption types (RFC 3961/4757) and which are weak enough to roast.
ETYPE_NAMES = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "rc4-hmac",
}
WEAK_ETYPES = frozenset({1, 3, 23})
