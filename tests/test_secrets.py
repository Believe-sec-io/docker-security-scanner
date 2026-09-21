"""Tests de la detection de secrets (motifs, placeholders, entropie)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import secrets  # noqa: E402


class SecretDetectionTests(unittest.TestCase):
    """Verifie les motifs connus et le filtrage des faux positifs."""

    def test_detects_aws_access_key(self):
        reason = secrets.judge_value("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        self.assertIsNotNone(reason)
        self.assertIn("AWS", reason)

    def test_detects_github_token(self):
        token = "ghp_" + "a" * 36
        self.assertIsNotNone(secrets.judge_value("TOKEN", token))

    def test_detects_private_key_block(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow"
        self.assertTrue(secrets.scan_text_for_secrets(text))

    def test_detects_connection_string(self):
        reason = secrets.judge_value("DATABASE_URL", "postgres://admin:S3cr3t@db:5432/app")
        self.assertIsNotNone(reason)

    def test_ignores_placeholders_and_references(self):
        for value in ("changeme", "${DB_PASSWORD}", "<votre-cle>", "example", "xxx", ""):
            with self.subTest(value=value):
                self.assertIsNone(secrets.judge_value("DB_PASSWORD", value))

    def test_ignores_innocuous_variables(self):
        self.assertIsNone(secrets.judge_value("APP_PORT", "8080"))
        self.assertIsNone(secrets.judge_value("NODE_ENV", "production"))

    def test_entropy_helpers(self):
        self.assertLess(secrets.shannon_entropy("aaaa"), 1.0)
        self.assertGreater(secrets.shannon_entropy("3fD9xQ2pL7mZ1tRb"), 3.4)
        self.assertTrue(secrets.is_high_entropy("3fD9xQ2pL7mZ1tRbA8cV"))
        self.assertFalse(secrets.is_high_entropy("/usr/local/bin/python3"))

    def test_redaction_masks_value(self):
        masked = secrets.redact("SuperSecretPassword123")
        self.assertNotIn("Secret", masked)
        self.assertTrue(masked.startswith("Supe"))

    def test_credential_paths(self):
        self.assertEqual("Env file", secrets.credential_path_label("/app/.env"))
        self.assertEqual("AWS credentials", secrets.credential_path_label("./home/app/.aws/credentials"))
        self.assertEqual("SSH private key", secrets.credential_path_label("root/.ssh/id_rsa"))
        self.assertIsNone(secrets.credential_path_label("/app/main.py"))

    def test_scan_mapping_reports_only_secrets(self):
        results = secrets.scan_mapping_for_secrets(
            {"DB_PASSWORD": "hunter2SecretValue", "APP_ENV": "production", "API_KEY": "changeme"}
        )
        names = [label for label, _masked in results]
        self.assertEqual(1, len(names))
        self.assertIn("DB_PASSWORD", names[0])

    def test_private_ip_detection(self):
        self.assertTrue(secrets.is_private_ip("10.0.0.5"))
        self.assertFalse(secrets.is_private_ip("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
