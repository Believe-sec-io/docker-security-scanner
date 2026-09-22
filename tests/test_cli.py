"""Tests of the command line interface (options, exit codes, output)."""

from __future__ import annotations

import io
import json

import pytest

from src.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, build_parser, main

INSECURE_DOCKERFILE = "FROM ubuntu:latest\nUSER root\nRUN chmod 777 /app\n"
SECURE_DOCKERFILE = "FROM alpine:3.20\nUSER 10001\nHEALTHCHECK CMD true\n"


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Run the CLI with captured streams and return ``(code, stdout, stderr)``."""
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def insecure_file(tmp_path):
    """Write the insecure Dockerfile sample and return its path."""
    target = tmp_path / "Dockerfile"
    target.write_text(INSECURE_DOCKERFILE, encoding="utf-8")
    return str(target)


@pytest.fixture()
def secure_file(tmp_path):
    """Write the hardened Dockerfile sample and return its path."""
    target = tmp_path / "Dockerfile.secure"
    target.write_text(SECURE_DOCKERFILE, encoding="utf-8")
    return str(target)


class TestParser:
    def test_defaults_are_ci_friendly(self) -> None:
        args = build_parser().parse_args(["Dockerfile"])
        assert args.kind == "auto"
        assert args.format == "console"
        assert args.severity == "info"
        assert args.fail_on == "high"
        assert args.ignore == []

    def test_ignore_accepts_repeated_and_comma_separated_values(self) -> None:
        args = build_parser().parse_args(["-i", "DF-001,CP-002", "--ignore", "CT-003", "x"])
        assert args.ignore == ["DF-001,CP-002", "CT-003"]

    def test_unknown_fail_on_value_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--fail-on", "sometimes", "x"])

    def test_version_is_printed(self, capsys) -> None:
        with pytest.raises(SystemExit) as excinfo:
            build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0
        assert "docker-security-scanner" in capsys.readouterr().out


class TestExitCodes:
    def test_findings_above_the_threshold_return_one(self, insecure_file) -> None:
        code, out, _ = run_cli(insecure_file, "--no-color")
        assert code == EXIT_FINDINGS
        assert "Findings:" in out

    def test_clean_scan_returns_zero(self, secure_file) -> None:
        code, out, _ = run_cli(secure_file, "--no-color")
        assert code == EXIT_OK
        assert "No insecure configuration found." in out

    def test_fail_on_none_never_fails(self, insecure_file) -> None:
        code, _, _ = run_cli(insecure_file, "--no-color", "--fail-on", "none")
        assert code == EXIT_OK

    def test_fail_on_critical_only_reacts_to_critical(self, tmp_path) -> None:
        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine:3.20\nUSER root\nHEALTHCHECK CMD true\n", encoding="utf-8")
        code, _, _ = run_cli(str(target), "--no-color", "--fail-on", "critical")
        assert code == EXIT_OK  # only HIGH findings

    def test_a_missing_target_returns_the_error_code(self) -> None:
        code, out, _ = run_cli("does-not-exist", "--no-color")
        assert code == EXIT_ERROR
        assert "no such file or directory" in out

    def test_unknown_rule_in_ignore_is_a_usage_error(self, insecure_file) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main([insecure_file, "--ignore", "ZZ-001"])
        assert excinfo.value.code == 2


class TestReportFormats:
    def test_json_report_is_machine_readable(self, insecure_file) -> None:
        code, out, _ = run_cli(insecure_file, "--format", "json")
        payload = json.loads(out)
        assert payload["total_findings"] > 0
        assert code == EXIT_FINDINGS

    def test_markdown_report_contains_a_table(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--format", "markdown")
        assert out.startswith("## Docker security scan:")
        assert "| Severity | Rule |" in out

    def test_sarif_report_is_valid_json(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--format", "sarif")
        assert json.loads(out)["version"] == "2.1.0"

    def test_output_option_writes_a_file_and_keeps_stdout_empty(self, insecure_file, tmp_path) -> None:
        destination = tmp_path / "report.json"
        code, out, _ = run_cli(insecure_file, "--format", "json", "--output", str(destination))
        assert out == ""
        assert json.loads(destination.read_text(encoding="utf-8"))["total_findings"] > 0
        assert code == EXIT_FINDINGS

    def test_output_option_creates_the_missing_directories(self, insecure_file, tmp_path) -> None:
        destination = tmp_path / "reports" / "nested" / "report.json"
        run_cli(insecure_file, "--format", "json", "-o", str(destination))
        assert destination.is_file()

    def test_no_color_is_respected(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--format", "console", "--no-color")
        assert "\033[" not in out

    def test_show_remediation_adds_the_fix(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--no-color", "--show-remediation")
        assert "fix:" in out

    def test_no_evidence_hides_the_observed_values(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--no-color", "--no-evidence")
        assert "evidence:" not in out


class TestFilters:
    def test_ignore_removes_a_rule_from_the_report(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--no-color", "--ignore", "DF-007")
        assert "DF-007" not in out
        assert "DF-002" in out

    def test_severity_filters_lower_severities(self, insecure_file) -> None:
        _, out, _ = run_cli(insecure_file, "--no-color", "--severity", "high")
        assert "DF-002" in out
        assert "DF-007" not in out  # MEDIUM

    def test_kind_overrides_the_detection(self, tmp_path) -> None:
        target = tmp_path / "config.txt"
        target.write_text(INSECURE_DOCKERFILE, encoding="utf-8")
        code, out, _ = run_cli(str(target), "--kind", "dockerfile", "--no-color")
        assert code == EXIT_FINDINGS
        assert "DF-002" in out

    def test_a_directory_is_scanned_recursively(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text(INSECURE_DOCKERFILE, encoding="utf-8")
        (tmp_path / "daemon.json").write_text('{"icc": true}', encoding="utf-8")
        code, out, _ = run_cli(str(tmp_path), "--no-color")
        assert code == EXIT_FINDINGS
        assert "Sources scanned: 2" in out


class TestStdin:
    def test_stdin_with_an_explicit_kind(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(INSECURE_DOCKERFILE))
        code, out, _ = run_cli("--stdin", "--kind", "dockerfile", "--no-color")
        assert code == EXIT_FINDINGS
        assert "DF-002" in out

    def test_stdin_detects_the_kind_from_the_content(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(INSECURE_DOCKERFILE))
        code, out, _ = run_cli("--stdin", "--no-color")
        assert code == EXIT_FINDINGS
        assert "<stdin>" in out

    def test_empty_stdin_is_an_error(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
        code, _, err = run_cli("--stdin", "--kind", "dockerfile")
        assert code == EXIT_ERROR
        assert "nothing to scan on stdin" in err


class TestListRules:
    def test_console_listing_groups_by_category(self) -> None:
        code, out, _ = run_cli("--list-rules")
        assert code == EXIT_OK
        assert "df-001" in out.lower()
        assert "rule catalog" in out

    def test_json_listing_exposes_the_metadata(self) -> None:
        _, out, _ = run_cli("--list-rules", "--format", "json")
        catalog = json.loads(out)
        assert len(catalog) == 61
        assert {"id", "title", "severity", "category", "remediation"} <= set(catalog[0])

    def test_markdown_listing_generates_the_documentation(self) -> None:
        _, out, _ = run_cli("--list-rules", "--format", "markdown")
        assert out.startswith("# Rule catalog")
        assert "| `DF-001` |" in out

    def test_sarif_listing_is_rejected(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--list-rules", "--format", "sarif"])
        assert excinfo.value.code == 2
