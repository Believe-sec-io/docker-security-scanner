# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-22

### Added

* **61 rules** split in four families, each documented with its severity, the
  CIS/OWASP reference it comes from and a concrete remediation:
  * `DF-001` … `DF-015` — Dockerfile and image build;
  * `CP-001` … `CP-016` — Docker Compose services;
  * `DM-001` … `DM-013` — Docker daemon configuration (file and host mode);
  * `CT-001` … `CT-017` — running containers (`docker inspect`).
* Four input modes: Dockerfile, Compose file, `daemon.json`, `docker inspect`
  output, plus `docker info` output for the daemon flags of a running host.
* Kind detection from the file name (and from the content for stdin), with an
  explicit `--kind` override.
* Four report formats: console (colour, optional evidence and remediation),
  JSON, Markdown (ready for a pull-request comment) and SARIF 2.1.0 (code
  scanning tab of a forge).
* A CI-oriented CLI: `--severity` to filter, `--fail-on` to choose the exit
  code threshold, `--ignore` (validated against the catalog), `--stdin`,
  `--output`, `--list-rules` and documented exit codes (`0`, `1`, `2`, `3`).
* Credential detection that never leaks a value: a finding reports the variable
  name and the length of the secret (`<redacted 15 chars>`), never the secret.
* Hardened and deliberately insecure samples in `examples/`, locked in both
  directions by `tests/test_examples.py` (the hardened ones must stay clean, the
  insecure ones must keep reporting their rules).
* 370 tests, a GitHub Actions workflow that runs the suite on Linux and Windows
  and scans the examples with the tool itself.

### Security

* `yaml.safe_load` is used everywhere: a configuration file coming from a
  repository can never instantiate arbitrary Python objects.
* Host mode (`docker info`) only reports what the output can actually prove, so
  a field the command does not expose is never turned into a false positive.

[1.0.0]: https://github.com/Believe-sec-io/docker-security-scanner/releases/tag/v1.0.0
