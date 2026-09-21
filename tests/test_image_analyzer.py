"""Tests de l'analyse d'image hors-ligne (archive docker save synthetique)."""

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import image_analyzer  # noqa: E402
from scanner.image_analyzer import ImageScanOptions  # noqa: E402


def _make_tar(members):
    """Construit une archive tar en memoire : {nom: octets}."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in members.items():
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            info.mtime = 1700000000
            tar.addfile(info, io.BytesIO(raw))
    buffer.seek(0)
    return buffer.read()


def build_test_image(root, user="", env=None, history_extra=(), layer_files=None):
    """Cree une fausse image docker-save minimale sur disque."""
    env = env if env is not None else []
    layer_files = layer_files or {}
    layer_name = "abc123/layer.tar"
    layer_tar = _make_tar(layer_files)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2024-01-01T00:00:00Z",
        "docker_version": "24.0.0",
        "config": {
            "User": user,
            "Env": env,
            "Cmd": ["python", "app.py"],
            "WorkingDir": "/app",
            "ExposedPorts": {"8080/tcp": {}},
            "Labels": {"org.opencontainers.image.title": "demo"},
        },
        "rootfs": {"diff_ids": ["sha256:abc123"]},
        "history": (
            [{"created_by": "FROM python:3.12-slim"}]
            + [{"created_by": extra} for extra in history_extra]
        ),
    }
    manifest = [{
        "Config": "config.json",
        "RepoTags": ["demo:1.0"],
        "Layers": [layer_name],
    }]
    path = os.path.join(root, "image.tar")
    with tarfile.open(path, "w") as tar:
        for name, payload in {
            "manifest.json": json.dumps(manifest),
            "config.json": json.dumps(config),
            layer_name: layer_tar,
        }.items():
            raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return path


def rule_ids(findings):
    return {f.rule_id for f in findings}


class ImageAnalyzerTests(unittest.TestCase):
    """Verifie les controles image sur une archive synthetique."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_clean_image_has_no_serious_findings(self):
        path = build_test_image(self.tmp.name, user="10001",
                                layer_files={"app/main.py": b"print('ok')"})
        findings, meta = image_analyzer.scan_image_tar(path)
        serious = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        self.assertEqual([], [f.rule_id for f in serious])
        self.assertEqual(["demo:1.0"], meta["repo_tags"])

    def test_root_user_secret_and_missing_healthcheck(self):
        path = build_test_image(
            self.tmp.name, user="",
            env=["DB_PASSWORD=SuperSecretValue123!"],
            layer_files={"app/main.py": b"ok"},
        )
        findings, _meta = image_analyzer.scan_image_tar(path)
        detected = rule_ids(findings)
        self.assertIn("DS-IMG-001", detected)
        self.assertIn("DS-IMG-003", detected)
        self.assertIn("DS-IMG-002", detected)
        secret = [f for f in findings if f.rule_id == "DS-IMG-003"][0]
        self.assertNotIn("SuperSecretValue123", secret.evidence)

    def test_history_secret_and_eol_base_detected(self):
        path = build_test_image(
            self.tmp.name, user="10001",
            history_extra=["RUN echo AKIAIOSFODNN7EXAMPLE",
                           "/bin/sh -c #(nop) FROM ubuntu:18.04"],
            layer_files={"app/main.py": b"ok"},
        )
        findings, _meta = image_analyzer.scan_image_tar(path)
        detected = rule_ids(findings)
        self.assertIn("DS-IMG-007", detected)
        self.assertIn("DS-IMG-018", detected)

    def test_sensitive_files_and_writable_bits(self):
        layer_buf = io.BytesIO()
        with tarfile.open(fileobj=layer_buf, mode="w") as layer:
            member = tarfile.TarInfo(name="home/app/.aws/credentials")
            member.size = 3
            layer.addfile(member, io.BytesIO(b"key"))
            bad = tarfile.TarInfo(name="app/run.sh")
            bad.size = 2
            bad.mode = 0o777
            layer.addfile(bad, io.BytesIO(b"hi"))
        path = build_test_image(self.tmp.name, user="10001", layer_files={})
        with tarfile.open(path, "r") as original:
            members = {m.name: original.extractfile(m).read()
                       for m in original.getmembers() if m.isfile()}
        members["abc123/layer.tar"] = layer_buf.getvalue()
        with tarfile.open(path, "w") as rebuilt:
            for name, raw in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(raw)
                rebuilt.addfile(info, io.BytesIO(raw))
        findings, _meta = image_analyzer.scan_image_tar(
            path, options=ImageScanOptions(scan_layer_content=True))
        detected = rule_ids(findings)
        self.assertIn("DS-IMG-004", detected)
        self.assertIn("DS-IMG-006", detected)

    def test_format_size(self):
        self.assertEqual("512 o", image_analyzer.format_size(512))
        self.assertEqual("2.0 Ko", image_analyzer.format_size(2048))


if __name__ == "__main__":
    unittest.main()

