"""Tests for the parsing helpers and the credential heuristics."""

from __future__ import annotations

import pytest

from src import secrets
from src.constants import is_dangerous_capability, is_sensitive_host_path, mutable_image_reference
from src.parsers import (
    as_bool,
    as_mapping,
    as_sequence,
    as_text_list,
    find_line,
    iter_files,
    join_continuations,
    parse_dockerfile,
    parse_json_text,
    parse_yaml_text,
    strip_quotes,
    unquote_command,
)


class TestDockerfileParsing:
    def test_parses_instruction_and_argument(self) -> None:
        instructions = parse_dockerfile("FROM alpine:3.20\nRUN echo hi\n")
        assert instructions == [(1, "FROM", "alpine:3.20"), (2, "RUN", "echo hi")]

    def test_uppercases_the_instruction_only(self) -> None:
        assert parse_dockerfile("from Alpine:3.20\n")[0] == (1, "FROM", "Alpine:3.20")

    def test_joins_continuation_lines(self) -> None:
        text = "RUN apt-get update \\\n    && apt-get install -y curl\n"
        instructions = parse_dockerfile(text)
        assert len(instructions) == 1
        assert instructions[0][0] == 1
        assert "apt-get install -y curl" in instructions[0][2]

    def test_continuation_survives_an_inline_comment(self) -> None:
        text = "RUN echo a \\\n# a comment inside the instruction\n    && echo b\n"
        assert len(parse_dockerfile(text)) == 1

    def test_ignores_comment_lines(self) -> None:
        assert parse_dockerfile("# comment\nFROM alpine\n") == [(2, "FROM", "alpine")]

    def test_keeps_the_line_number_of_the_first_line(self) -> None:
        assert join_continuations("# header\n\nFROM alpine\n") == [(3, "FROM alpine")]

    def test_unterminated_continuation_is_kept(self) -> None:
        assert join_continuations("RUN echo \\\n") == [(1, "RUN echo")]

    def test_json_array_command_is_recognised(self) -> None:
        assert unquote_command('["python", "-m", "app"]') == ["python", "-m", "app"]

    def test_shell_form_command_is_not_a_json_array(self) -> None:
        assert unquote_command("python -m app") is None
        assert unquote_command('["python", 3]') is None
        assert unquote_command('["python",') is None


class TestCoercion:
    @pytest.mark.parametrize("value", [True, 1, "true", "True", "yes", "on", "1"])
    def test_as_bool_accepts_docker_truthy_values(self, value: object) -> None:
        assert as_bool(value) is True

    @pytest.mark.parametrize("value", [False, 0, "false", "False", "no", "off", "", None])
    def test_as_bool_rejects_everything_else(self, value: object) -> None:
        assert as_bool(value) is False

    def test_as_mapping_returns_a_plain_dict(self) -> None:
        assert as_mapping({"a": 1}) == {"a": 1}
        assert as_mapping(None) == {}
        assert as_mapping(["a"]) == {}

    def test_as_sequence_wraps_scalars(self) -> None:
        assert as_sequence("a") == ["a"]
        assert as_sequence(None) == []
        assert as_sequence(("a", "b")) == ["a", "b"]

    def test_as_text_list_trims_and_drops_empties(self) -> None:
        assert as_text_list([" a ", "", None, 3]) == ["a", "3"]

    def test_strip_quotes_removes_one_pair(self) -> None:
        assert strip_quotes('"value"') == "value"
        assert strip_quotes("'value'") == "value"
        assert strip_quotes('"value') == '"value'

    def test_find_line_locates_a_pattern(self) -> None:
        text = "services:\n  api:\n    privileged: true\n"
        assert find_line(text, r"privileged\s*:\s*true") == 3
        assert find_line(text, "absent") == 0


class TestStructuredParsing:
    def test_parse_json_raises_a_readable_error(self) -> None:
        with pytest.raises(ValueError, match="invalid JSON"):
            parse_json_text("{oops}")

    def test_parse_yaml_raises_a_readable_error(self) -> None:
        with pytest.raises(ValueError, match="invalid YAML"):
            parse_yaml_text("a: [1,\n")

    def test_parse_yaml_does_not_build_arbitrary_objects(self) -> None:
        with pytest.raises(ValueError, match="invalid YAML"):
            parse_yaml_text("!!python/object/apply:os.system ['echo pwned']")

    def test_iter_files_matches_names_and_suffixes(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
        (tmp_path / "compose.yml").write_text("services: {}\n", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")

        by_name = iter_files(str(tmp_path), names=["dockerfile"])
        assert [path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for path in by_name] == ["Dockerfile"]

        assert len(iter_files(str(tmp_path), suffixes=[".yml"])) == 1

    def test_iter_files_on_a_single_file(self, tmp_path) -> None:
        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine\n", encoding="utf-8")
        assert iter_files(str(target)) == [str(target)]


class TestCredentialHeuristics:
    @pytest.mark.parametrize(
        "name",
        ["DB_PASSWORD", "API_KEY", "jwt_secret", "GITHUB_TOKEN", "NPM_TOKEN", "client-secret"],
    )
    def test_recognises_credential_names(self, name: str) -> None:
        assert secrets.looks_like_secret_name(name) is True

    @pytest.mark.parametrize("name", ["PORT", "PATH", "APP_ENV", "LOG_LEVEL", ""])
    def test_ignores_ordinary_names(self, name: str) -> None:
        assert secrets.looks_like_secret_name(name) is False

    @pytest.mark.parametrize("value", ["", "changeme", "xxx", "********", "<password>", None])
    def test_placeholders_are_not_literals(self, value: object) -> None:
        assert secrets.is_literal_value(value) is False

    @pytest.mark.parametrize(
        "value",
        ["${DB_PASSWORD}", "$DB_PASSWORD", "/run/secrets/db_password", "/var/run/secrets/token"],
    )
    def test_interpolations_are_not_literals(self, value: str) -> None:
        assert secrets.is_literal_value(value) is False

    def test_real_value_is_a_literal(self) -> None:
        assert secrets.is_literal_value("hunter2-hunter2") is True

    def test_split_assignment_handles_both_forms(self) -> None:
        assert secrets.split_assignment("KEY=value") == ("KEY", "value")
        assert secrets.split_assignment("KEY") == ("KEY", "")
        assert secrets.split_assignment("") == ("", "")

    def test_inspect_assignments_reports_only_literal_secrets(self) -> None:
        found = secrets.inspect_assignments(
            ["DB_PASSWORD=hunter2", "API_TOKEN=${API_TOKEN}", "PORT=8080", "JWT_SECRET"]
        )
        assert found == [("DB_PASSWORD", "hunter2")]

    def test_first_secret_in_text_scans_a_command_line(self) -> None:
        assert secrets.first_secret_in_text("mysql PASSWORD=hunter2 -u root") == (
            "PASSWORD",
            "hunter2",
        )
        assert secrets.first_secret_in_text("echo hello") is None

    def test_redact_never_returns_the_value(self) -> None:
        assert "hunter2" not in secrets.redact("hunter2")
        assert secrets.redact("") == "<empty>"


class TestSecurityConstants:
    @pytest.mark.parametrize(
        "path",
        ["/", "/etc", "/etc/kubernetes", "/proc", "/sys/fs/cgroup", "/var/run", "/root/.ssh"],
    )
    def test_sensitive_host_paths(self, path: str) -> None:
        assert is_sensitive_host_path(path) is True

    @pytest.mark.parametrize(
        "path",
        ["", "./data", "/etc/hosts", "/etc/resolv.conf", "/home/app/data", "api-data"],
    )
    def test_harmless_host_paths(self, path: str) -> None:
        assert is_sensitive_host_path(path) is False

    @pytest.mark.parametrize("capability", ["ALL", "SYS_ADMIN", "CAP_NET_ADMIN", "sys_ptrace"])
    def test_dangerous_capabilities(self, capability: str) -> None:
        assert is_dangerous_capability(capability) is True

    @pytest.mark.parametrize("capability", ["CHOWN", "SETUID", "NET_BIND_SERVICE", ""])
    def test_default_capabilities_are_not_dangerous(self, capability: str) -> None:
        assert is_dangerous_capability(capability) is False

    @pytest.mark.parametrize(
        "reference",
        ["nginx", "nginx:latest", "ghcr.io/a/b:stable", "localhost:5000/app:dev"],
    )
    def test_mutable_image_references(self, reference: str) -> None:
        assert mutable_image_reference(reference) is True

    @pytest.mark.parametrize(
        "reference",
        ["nginx:1.27", "ghcr.io/a/b@sha256:abc", "python:3.12.7-slim"],
    )
    def test_pinned_image_references(self, reference: str) -> None:
        assert mutable_image_reference(reference) is False
