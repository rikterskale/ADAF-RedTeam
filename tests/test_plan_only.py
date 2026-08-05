"""Plan-only and gate behavior. Phase 0 executes nothing."""

from adaf_redteam.__main__ import main
from adaf_redteam.authz import GateError, authorize, load_engagement
from adaf_redteam.capabilities.registry import get_descriptor, list_descriptors

ENG = "examples/engagement.example.json"


def test_adapter_presence_matches_readiness():
    # Invariant: a capability has an executable adapter iff it is no longer PlanOnly.
    for d in list_descriptors():
        if d.adapter is None:
            assert d.readiness == "PlanOnly", f"{d.capability_id}: no adapter but not PlanOnly"
        else:
            assert d.readiness != "PlanOnly", f"{d.capability_id}: has adapter but still PlanOnly"


def test_wired_adapters_are_not_lab_certified_yet():
    # Phase 1 ships adapters whose live collector is uncertified; results are flagged.
    for d in list_descriptors():
        if d.adapter is not None:
            assert d.lab_certified is False, f"{d.capability_id} certified without a lab test?"


def test_plan_only_run_succeeds(tmp_path, capsys):
    rc = main([
        "run", "--engagement", ENG, "--capability", "asrep-roast-validation",
        "--source-address", "192.0.2.25", "--plan-only", "--out", str(tmp_path),
    ])
    assert rc == 0
    assert (tmp_path / "plan.json").exists()
    assert (tmp_path / "manifest.json").exists()
    out = capsys.readouterr().out
    assert "asrep-roast-validation" in out
    assert "decisionTrace" in out
    assert "Uncertified:" in out


def test_run_without_plan_only_reports_no_adapter(tmp_path, capsys, monkeypatch):
    # Every registered capability now has an adapter, so synthesize a PlanOnly one
    # to exercise the "no executable adapter" branch.
    import adaf_redteam.__main__ as m
    from adaf_redteam.authz.gates import AuthorizedAction
    from adaf_redteam.capabilities.registry import CapabilityDescriptor
    fake = CapabilityDescriptor("fake-planonly", "Fake", "test", "PlanOnly", "T1000")
    monkeypatch.setattr(m, "get_descriptor", lambda cid: fake)
    monkeypatch.setattr(m, "authorize", lambda *a, **k: AuthorizedAction(
        "fake-planonly", "t", "T1000", "192.0.2.25", False, False, 1, 0))
    rc = m.main([
        "run", "--engagement", ENG, "--capability", "fake-planonly",
        "--source-address", "192.0.2.25", "--target", "t", "--out", str(tmp_path),
    ])
    assert rc == 4
    assert "ADAF-RT-E202" in capsys.readouterr().err


def test_gate_refuses_unauthorized_source_address():
    eng = load_engagement(ENG)
    d = get_descriptor("asrep-roast-validation")
    try:
        authorize(eng, d, target="svc-asrep01", source_address="10.0.0.1", plan_only=True)
        assert False, "should have raised"
    except GateError as e:
        assert "source address" in str(e)
        assert e.code == "ADAF-RT-E102"


def test_gate_refuses_unlisted_target():
    eng = load_engagement(ENG)
    d = get_descriptor("asrep-roast-validation")
    try:
        authorize(eng, d, target="not-authorized", source_address="192.0.2.25", plan_only=True)
        assert False, "should have raised"
    except GateError as e:
        assert "target" in str(e)


def test_gate_refuses_capability_not_in_engagement():
    eng = load_engagement(ENG)
    d = get_descriptor("golden-silver-ticket")  # not listed in example engagement
    try:
        authorize(eng, d, target="krbtgt", source_address="192.0.2.25", plan_only=True)
        assert False, "should have raised"
    except GateError as e:
        assert "not listed" in str(e)


def test_evasion_capability_requires_detection_notification():
    # The adversary-emulation capability must not run (non-plan) without ROE notification.
    eng = load_engagement(ENG)
    d = get_descriptor("adversary-emulation-evasion")
    # example engagement DOES supply detectionNotification, so this should pass the gate:
    action = authorize(eng, d, target="WIN-LAB01", source_address="192.0.2.25", plan_only=False)
    assert action.state_changing is True


def test_doctor_reports_local_prerequisites(capsys):
    rc = main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ADAF-RedTeam doctor" in out
    assert "no target contact" in out


def test_list_capabilities_explains_uncertified_availability(capsys):
    assert main(["list-capabilities"]) == 0
    out = capsys.readouterr().out
    assert "AVAILABILITY" in out
    assert "Uncertified:" in out
