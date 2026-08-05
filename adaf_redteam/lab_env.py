"""Lab-environment helpers for certification-gated live collectors.

These helpers exist only to make the disposable-lab certification path
(documented in docs/CERTIFICATION.md and the tests/test_certification_*.py
files) reliable. They never relax authorization, containment, or redaction.

When ADAF_RT_LAB is not "1", every helper returns None / defaults so production
engagement runs are unaffected.
"""

from __future__ import annotations

import os


def lab_opt_in() -> bool:
    """True only when the operator has explicitly acknowledged disposable-lab work."""
    return os.environ.get("ADAF_RT_LAB") == "1"


def lab_dc() -> str | None:
    """Optional KDC / LDAP server override for certification runs.

    Certification tests set ADAF_RT_LAB_DC. When absent, callers fall back to
    the domain name (Windows KDCs usually answer on the domain SRV record).
    """
    if not lab_opt_in():
        return None
    value = os.environ.get("ADAF_RT_LAB_DC", "").strip()
    return value or None


def lab_bind_user() -> str | None:
    """Optional LDAP bind principal for certification runs.

    Certification tests set ADAF_RT_LAB_BIND_USER. Production runs continue to
    use whatever identity the engagement / operator supplies through normal
    means (Kerberos ccache is preferred).
    """
    if not lab_opt_in():
        return None
    value = os.environ.get("ADAF_RT_LAB_BIND_USER", "").strip()
    return value or None


def lab_bind_password() -> str | None:
    """Optional SIMPLE-bind password for certification runs.

    Prefer Kerberos ccache. Only used when ADAF_RT_LAB=1 and the operator
    explicitly supplies a password; never logged or returned to callers beyond
    the LDAP source constructor.
    """
    if not lab_opt_in():
        return None
    value = os.environ.get("ADAF_RT_LAB_BIND_PASSWORD")
    return value if value else None
