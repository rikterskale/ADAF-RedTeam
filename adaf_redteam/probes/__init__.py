"""Live protocol probes for Kerberos, Netlogon, ADCS, RBCD, ShadowCred, coercion,
relay, credential-access, execution, forgery, and emulation.

Every probe is the lab-certification boundary for its capability. Implemented
and offline-tested today:

  - Kerberos AS-REP / TGS metadata probes (never touch cipher bytes)
  - Zerologon SAFE detection (bounded zero-challenge auth; never password-set)

State-changing writers (RBCD, ShadowCred, ESC1 enrollment, coercion/relay, etc.)
still raise NotImplementedError by design. Analyzers are unit-tested; the live
probe is the certification boundary. Use --fixture to run the pipeline offline.
All capabilities ship lab_certified=False until a disposable-lab evidence package
promotes them.
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
