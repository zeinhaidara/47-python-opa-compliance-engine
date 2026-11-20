import subprocess

import pytest

from compliance import runner
from compliance.cli import main
from compliance.runner import (
    FAIL,
    NOT_EVALUATED,
    PASS,
    MappingError,
    OpaError,
    attach,
    check_input,
    evaluate,
    find_opa,
    load_controls,
)
from tests.conftest import FIXTURES, ROOT

RULES = {
    "s3_public_access_blocked",
    "s3_access_logging",
    "storage_encrypted",
    "sg_no_open_admin_ports",
    "iam_console_user_mfa",
    "cloudtrail_multi_region",
}


# --- real opa --------------------------------------------------------------------


def test_evaluate_with_real_opa(opa):
    rules, results = evaluate(opa, ROOT / "policies", FIXTURES / "resources.json")
    assert rules == RULES
    fails = {(r.rule, r.resource) for r in results if r.status == FAIL}
    assert fails == {
        ("s3_public_access_blocked", "arn:aws:s3:::public-assets-example-com"),
        ("s3_access_logging", "arn:aws:s3:::public-assets-example-com"),
        ("storage_encrypted", "vol-0123456789abcdef0"),
        ("sg_no_open_admin_ports", "sg-0123456789abcdef0"),
        ("iam_console_user_mfa", "arn:aws:iam::123456789012:user/alice"),
    }
    # good bucket x3, public bucket encryption, bob MFA
    assert sum(r.status == PASS for r in results) == 5


def test_control_rollup(opa):
    rules, results = evaluate(opa, ROOT / "policies", FIXTURES / "resources.json")
    controls = {c.id: c for c in load_controls(ROOT / "controls.yaml", rules)}
    attach(list(controls.values()), results)
    assert controls["SOC2-CC6.1"].status == FAIL
    assert controls["ISO27001-A.8.24"].status == FAIL
    # Logging control has a failing bucket even with no CloudTrail in the input.
    assert controls["ISO27001-A.8.15"].status == FAIL


def test_not_evaluated_when_nothing_in_scope(opa):
    rules, results = evaluate(opa, ROOT / "policies", FIXTURES / "volumes_only.json")
    controls = {c.id: c for c in load_controls(ROOT / "controls.yaml", rules)}
    attach(list(controls.values()), results)
    assert controls["ISO27001-A.8.24"].status == PASS
    assert controls["SOC2-CC6.1"].status == NOT_EVALUATED
    assert controls["ISO27001-A.8.15"].status == NOT_EVALUATED


def test_cli_report(opa, tmp_path):
    out = tmp_path / "r.md"
    code = main(["--input", str(FIXTURES / "resources.json"), "--opa", opa, "--output", str(out)])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "It is not an audit" in text
    assert "Controls: 7 (0 pass, 7 fail, 0 not evaluated)." in text
    assert "| SOC2-CC6.1 | SOC 2 |" in text
    assert "| SOC2-CC6.1 | iam_console_user_mfa | arn:aws:iam::123456789012:user/alice |" in text


def test_cli_fail_on_fail(opa, tmp_path):
    args = [
        "--input",
        str(FIXTURES / "resources.json"),
        "--opa",
        opa,
        "--output",
        str(tmp_path / "r.md"),
        "--fail-on-fail",
    ]
    assert main(args) == 2
    clean = [
        "--input",
        str(FIXTURES / "volumes_only.json"),
        "--opa",
        opa,
        "--output",
        str(tmp_path / "c.md"),
        "--fail-on-fail",
    ]
    assert main(clean) == 0


def test_cli_policy_error_exits_1(opa, tmp_path, capsys):
    bad = tmp_path / "policies"
    bad.mkdir()
    (bad / "broken.rego").write_text("package compliance\n\nreport := {\n", encoding="utf-8")
    code = main(["--input", str(FIXTURES / "resources.json"), "--opa", opa, "--policies", str(bad)])
    assert code == 1
    assert "OpaError" in capsys.readouterr().err


# --- failure paths without opa --------------------------------------------------------


def test_missing_opa_fails_loudly(tmp_path):
    with pytest.raises(OpaError, match="not found"):
        find_opa(str(tmp_path / "no-such-opa"))


def test_missing_opa_cli_exit_1(tmp_path, capsys):
    code = main(["--input", str(FIXTURES / "resources.json"), "--opa", str(tmp_path / "nope")])
    assert code == 1
    assert "opa binary not found" in capsys.readouterr().err


def fake_run(stdout="", rc=0, stderr=""):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)

    return run


def test_nonzero_exit_raises(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", fake_run(rc=1, stderr="rego_parse_error"))
    with pytest.raises(OpaError, match="rego_parse_error"):
        evaluate("opa", ROOT / "policies", FIXTURES / "resources.json")


def test_undefined_query_raises(monkeypatch):
    # opa prints {} when the query is undefined; that must not read as "no failures".
    monkeypatch.setattr(runner.subprocess, "run", fake_run(stdout="{}"))
    with pytest.raises(OpaError, match="unexpected opa output"):
        evaluate("opa", ROOT / "policies", FIXTURES / "resources.json")


def test_garbage_output_raises(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", fake_run(stdout="not json"))
    with pytest.raises(OpaError):
        evaluate("opa", ROOT / "policies", FIXTURES / "resources.json")


def test_mapping_with_unknown_rule_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("controls:\n  - {id: X-1, framework: X, title: t, rules: [no_such_rule]}\n")
    with pytest.raises(MappingError, match="no_such_rule"):
        load_controls(p, RULES)


def test_duplicate_control_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "controls:\n"
        "  - {id: X-1, framework: X, title: t, rules: [storage_encrypted]}\n"
        "  - {id: X-1, framework: X, title: t, rules: [storage_encrypted]}\n"
    )
    with pytest.raises(MappingError, match="twice"):
        load_controls(p, RULES)


@pytest.mark.parametrize(
    "content",
    ['{"resources": []}', "[]", '{"resources": [{"id": "x", "type": "aws_s3_bucket"}]}'],
)
def test_bad_input_rejected(tmp_path, content):
    p = tmp_path / "in.json"
    p.write_text(content)
    with pytest.raises(ValueError):
        check_input(p)
