"""Plan-only and gate behavior. Phase 0 executes nothing."""

from adaf_redteam.__main__ import main
from adaf_redteam.authz import GateError, authorize, load_engagement
from adaf_redteam.capabilities.registry import get_descriptor, list_descriptors

ENG = "examples/engagement.example.json"


def test_every_capability_is_planonly_with_no_adapter():
    for d in list_descriptors():
        assert d.adapter is None, f"{d.capability_id} must have no adapter in Phase 0"


def test_plan_only_run_succeeds(tmp_path, capsys):
    rc = main([
        "run", "--engagement", ENG, "--capability", "asrep-roast-validation",
        "--source-address", "192.0.2.25", "--plan-only", "--out", str(tmp_path),
    ])
    assert rc == 0
    assert (tmp_path / "plan.json").exists()
    out = capsys.readouterr().out
    assert "asrep-roast-validation" in out


def test_run_without_plan_only_reports_no_adapter(tmp_path, capsys):
    rc = main([
        "run", "--engagement", ENG, "--capability", "asrep-roast-validation",
        "--source-address", "192.0.2.25", "--out", str(tmp_path),
    ])
    assert rc == 4
    assert "NO EXECUTABLE ADAPTER" in capsys.readouterr().err


def test_gate_refuses_unauthorized_source_address():
    eng = load_engagement(ENG)
    d = get_descriptor("asrep-roast-validation")
    try:
        authorize(eng, d, target="svc-asrep01", source_address="10.0.0.1", plan_only=True)
        assert False, "should have raised"
    except GateError as e:
        assert "source address" in str(e)


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
