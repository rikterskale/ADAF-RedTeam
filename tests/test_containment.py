"""Containment probe: fails closed, verifies only internally-consistent lab decls."""

from adaf_redteam.containment import probe_domain


def _probe(**kw):
    base = {"engagement_declares_lab": True, "lab_ranges": ["10.10.0.0/16"],
            "lab_addresses": ["10.10.0.5"]}
    base.update(kw)
    return probe_domain("corp.contoso.test", **base)


def test_verified_when_all_declarations_consistent():
    p = _probe()
    assert p.verified is True
    assert p.environment == "disposable-lab"


def test_fails_when_lab_not_declared():
    assert _probe(engagement_declares_lab=False).verified is False


def test_fails_when_no_ranges():
    assert _probe(lab_ranges=[]).verified is False


def test_fails_when_no_addresses():
    assert _probe(lab_addresses=[]).verified is False


def test_fails_when_address_outside_range():
    p = _probe(lab_addresses=["192.0.2.9"])  # not in 10.10.0.0/16
    assert p.verified is False
    check = next(c for c in p.checks if c["name"] == "all-host-addresses-within-lab-ranges")
    assert "192.0.2.9" in check["detail"]


def test_fails_on_unparseable_address():
    assert _probe(lab_addresses=["not-an-ip"]).verified is False


def test_multiple_ranges_and_addresses():
    p = _probe(lab_ranges=["10.10.0.0/16", "172.16.0.0/12"],
               lab_addresses=["10.10.1.2", "172.16.5.5"])
    assert p.verified is True
