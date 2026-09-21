"""Tests de l'analyse statique des Dockerfiles."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import dockerfile_rules  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSECURE = os.path.join(PROJECT_ROOT, "examples", "insecure", "Dockerfile")
SECURE = os.path.join(PROJECT_ROOT, "examples", "secure", "Dockerfile")

VULNERABLE = """\
FROM ubuntu:18.04
ENV DB_PASSWORD=SuperSecretPassword123!
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | bash
RUN chmod -R 777 /app
EXPOSE 22
"""


def rule_ids(findings):
    """Identifiants des regles declenchees."""
    return {finding.rule_id for finding in findings}


class DockerfileParsingTests(unittest.TestCase):
    """Verifie la normalisation des instructions."""

    def test_parses_instructions_and_line_numbers(self):
        instructions = dockerfile_rules.parse_dockerfile("FROM alpine:3.20\n\n# commentaire\nRUN echo ok\n")
        self.assertEqual(["FROM", "RUN"], [i.keyword for i in instructions])
        self.assertEqual(1, instructions[0].line)
        self.assertEqual(4, instructions[1].line)

    def test_merges_continuation_lines(self):
        text = "FROM alpine:3.20\nRUN apk add --no-cache \\\n    curl \\\n    git\n"
        instructions = dockerfile_rules.parse_dockerfile(text)
        self.assertEqual(2, len(instructions))
        self.assertIn("git", instructions[1].arguments)
        self.assertEqual(2, instructions[1].line)

    def test_ignores_comments_and_empty_input(self):
        self.assertEqual([], dockerfile_rules.parse_dockerfile("# juste un commentaire\n\n"))

    def test_metadata_reports_multi_stage(self):
        text = "FROM python:3.12-slim AS builder\nRUN echo 1\nFROM python:3.12-slim\nRUN echo 2\n"
        metadata = dockerfile_rules.dockerfile_metadata(text)
        self.assertEqual(2, metadata["stages"])
        self.assertTrue(metadata["multi_stage"])


class DockerfileRuleTests(unittest.TestCase):
    """Verifie les regles declenchees selon le contenu."""

    def test_vulnerable_snippet_triggers_expected_rules(self):
        findings = dockerfile_rules.scan_dockerfile_text(VULNERABLE, target="test")
        detected = rule_ids(findings)
        for expected in ("DS-DF-002", "DS-DF-004", "DS-DF-005", "DS-DF-006", "DS-DF-007", "DS-DF-009", "DS-DF-014", "DS-DF-015"):
            with self.subTest(rule=expected):
                self.assertIn(expected, detected)

    def test_secrets_are_redacted_in_evidence(self):
        findings = [f for f in dockerfile_rules.scan_dockerfile_text(VULNERABLE, target="test") if f.rule_id == "DS-DF-007"]
        self.assertTrue(findings)
        self.assertNotIn("SuperSecretPassword123", findings[0].evidence)
        self.assertIn("********", findings[0].evidence)

    def test_insecure_example_triggers_many_rules(self):
        findings, metadata = dockerfile_rules.scan_dockerfile(INSECURE, context_dir=os.path.dirname(INSECURE))
        detected = rule_ids(findings)
        self.assertGreaterEqual(len(detected), 14, f"Seulement {sorted(detected)}")
        self.assertIn("DS-DF-018", detected)  # .dockerignore absent
        self.assertEqual("ubuntu:18.04", metadata["base_images"][0])

    def test_secure_example_has_no_medium_or_higher_finding(self):
        findings, _metadata = dockerfile_rules.scan_dockerfile(SECURE, context_dir=os.path.dirname(SECURE))
        serious = [f for f in findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        self.assertEqual([], [f"{f.rule_id}: {f.message}" for f in serious])

    def test_dockerignore_check_detects_missing_sensitive_patterns(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, ".dockerignore"), "w", encoding="utf-8") as handle:
                handle.write(".git\n")
            findings = dockerfile_rules.scan_dockerfile_text(
                "FROM alpine:3.20\nUSER 10001\nHEALTHCHECK CMD true\n",
                target="Dockerfile",
                context_dir=folder,
            )
        detected = rule_ids(findings)
        self.assertIn("DS-DF-019", detected)
        self.assertNotIn("DS-DF-018", detected)

    def test_pinned_and_patched_dockerfile_is_clean(self):
        text = (
            "FROM alpine:3.20\n"
            "LABEL maintainer=\"test@example.com\"\n"
            "USER 10001\n"
            "HEALTHCHECK CMD wget -q -O- http://127.0.0.1/ || exit 1\n"
        )
        findings = dockerfile_rules.scan_dockerfile_text(text, target="Dockerfile")
        self.assertEqual([], [f.rule_id for f in findings])


if __name__ == "__main__":
    unittest.main()
