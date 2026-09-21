"""Tests des rendus : console, JSON, HTML, Markdown."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.models import Report  # noqa: E402
from scanner import reporters  # noqa: E402
from scanner.rules import make_finding  # noqa: E402


def build_report():
    report = Report(target="demo:1.0", target_type="image")
    report.add(make_finding("DS-IMG-001", "root", "demo:1.0"))
    report.add(make_finding("DS-DF-003", "healthcheck", "demo:1.0"))
    report.sort_findings()
    return report


class ReportersTests(unittest.TestCase):
    """Les 4 formats doivent contenir les constats, sans fuite."""

    def test_console_contains_findings_and_score(self):
        text = reporters.render(build_report(), fmt="console", use_color=False)
        self.assertIn("DS-IMG-001", text)
        self.assertIn("Score de risque", text)

    def test_json_is_structured(self):
        payload = json.loads(reporters.render(build_report(), fmt="json"))
        self.assertEqual(2, payload["total_findings"])
        self.assertIn("summary", payload)
        self.assertEqual("demo:1.0", payload["target"])

    def test_html_is_standalone(self):
        page = reporters.render(build_report(), fmt="html")
        self.assertIn("<!DOCTYPE html>", page)
        self.assertIn("DS-DF-003", page)
        # Aucune ressource externe : pas de lien http(s) hormis les textes
        # de remediation HEALTHCHECK (http://...) qui ne sont pas des liens.
        cleaned = page.replace("http://127.0.0.1", "").replace("http://localhost", "")
        self.assertNotIn("http://", cleaned)
        self.assertNotIn('href="http', cleaned)
        self.assertNotIn('src="http', cleaned)

    def test_markdown_table(self):
        doc = reporters.render(build_report(), fmt="markdown")
        self.assertIn("| Gravite | Regle |", doc)
        self.assertIn("DS-IMG-001", doc)

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            reporters.render(build_report(), fmt="pdf")

    def test_empty_report(self):
        empty = Report(target="clean", target_type="dockerfile")
        self.assertIn("Aucun constat", reporters.render(empty, fmt="console",
                                                        use_color=False))


if __name__ == "__main__":
    unittest.main()
