"""Live protocol probes (Kerberos, Netlogon) for Phase 1 increment 2.

Unlike the LDAP reads in increment 1, these speak live protocol. Each live probe
is NOT lab-certified in this build (its methods raise), so capabilities using them
ship lab_certified=False and the CLI stamps results UNVALIDATED. Analyzers are
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
