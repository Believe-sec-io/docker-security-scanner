"""Tests du catalogue de regles et du modele de rapport."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import rules as rule_module  # noqa: E402
from scanner.models import Finding, Report, risk_label, severity_value  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_FILES = [
    os.path.join(PROJECT_ROOT, "docker_scanner.py"),
    os.path.join(PROJECT_ROOT, "scanner", "dockerfile_rules.py"),
    os.path.join(PROJECT_ROOT, "scanner", "image_analyzer.py"),
    os.path.join(PROJECT_ROOT, "scanner", "runtime_checks.py"),
]
RULE_ID_PATTERN = r'"DS-(DF|IMG|RT|GEN)-\d{3}"'


class RulesCatalogueTests(unittest.TestCase):
    """Verifie la coherence entre le code et rules/rules.json."""

    def setUp(self):
        self.rules = rule_module.load_rules()

    def test_catalogue_not_empty(self):
        self.assertGreaterEqual(len(self.rules), 45, "Le catalogue doit contenir au moins 45 regles.")

    def test_catalogue_entries_are_complete(self):
        for rule_id, definition in self.rules.items():
            with self.subTest(rule=rule_id):
                self.assertTrue(definition.get("title"), f"{rule_id} sans titre")
                self.assertTrue(definition.get("remediation"), f"{rule_id} sans remediation")
                self.assertIn(definition.get("severity"), ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
                self.assertIn(definition.get("category"), ("dockerfile", "image", "runtime"))

    def test_every_rule_used_in_code_exists_in_catalogue(self):
        import re

        referenced = set()
        for path in SOURCE_FILES:
            with open(path, "r", encoding="utf-8") as handle:
                referenced.update(re.findall(r"DS-[A-Z]{2,3}-\d{3}", handle.read()))
        self.assertTrue(referenced, "Aucun identifiant de regle trouve dans le code")
        unknown = sorted(rule_id for rule_id in referenced if rule_id not in self.rules)
        self.assertEqual([], unknown, f"Regles referencees mais absentes du catalogue : {unknown}")

    def test_make_finding_uses_catalogue_metadata(self):
        finding = rule_module.make_finding("DS-DF-002", "test", "Dockerfile", "L1")
        self.assertEqual(finding.title, self.rules["DS-DF-002"]["title"])
        self.assertEqual(finding.severity, self.rules["DS-DF-002"]["severity"])
        self.assertTrue(finding.remediation)


class ReportModelTests(unittest.TestCase):
    """Verifie le scoring, le filtrage et l'export du rapport."""

    def build_report(self):
        report = Report(target="demo:latest", target_type="image")
        report.add(rule_module.make_finding("DS-IMG-001", "root", "demo:latest"))
        report.add(rule_module.make_finding("DS-DF-003", "healthcheck", "demo:latest"))
        return report

    def test_counts_and_score(self):
        report = self.build_report()
        counts = report.counts()
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(report.risk_score(), 17)  # 15 (HIGH) + 2 (LOW)
        self.assertEqual(report.grade(), "C")  # seuils : 0=A, 10=B, 25=C
        self.assertEqual(report.worst_severity(), "HIGH")

    def test_filtered_by_severity_and_ignored_rules(self):
        report = self.build_report()
        high_only = report.filtered(min_severity="HIGH")
        self.assertEqual(len(high_only.findings), 1)
        ignored = report.filtered(ignore_rules=["DS-IMG-001"])
        self.assertEqual([f.rule_id for f in ignored.findings], ["DS-DF-003"])

    def test_has_findings_at_or_above(self):
        report = self.build_report()
        self.assertTrue(report.has_findings_at_or_above("HIGH"))
        self.assertTrue(report.has_findings_at_or_above("LOW"))
        self.assertFalse(report.has_findings_at_or_above("CRITICAL"))

    def test_to_dict_is_json_serialisable(self):
        import json

        payload = json.dumps(self.build_report().to_dict())
        self.assertIn("\"summary\"", payload)
        self.assertIn("\"findings\"", payload)
        self.assertGreater(len(payload), 200)

    def test_empty_report_is_clean(self):
        report = Report(target="clean", target_type="dockerfile")
        self.assertEqual(0, report.risk_score())
        self.assertEqual("A", report.grade())
        self.assertEqual("clean", risk_label(0))
        self.assertEqual(0, severity_value("INCONNUE"))


if __name__ == "__main__":
    unittest.main()
