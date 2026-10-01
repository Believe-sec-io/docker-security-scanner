# docker-security-scanner

[![CI](https://github.com/Believe-sec-io/docker-security-scanner/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Believe-sec-io/docker-security-scanner/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Audit the security configuration of a Docker setup — before it reaches a host.**

`docker-security-scanner` is a static analyser for the four places where a
container deployment becomes insecure: the **Dockerfile** that builds the image,
the **Compose file** that deploys it, the **daemon configuration** of the host
and the **running containers** themselves. It needs no Docker daemon and no root
access: it reads files and reports what is wrong, with the CIS/OWASP reference
and the exact fix for every finding.

```
$ docker-security-scanner examples/Dockerfile.insecure
Docker security scan: examples/Dockerfile.insecure

[CRIT] DF-006  Hardcoded secret in image
        at examples/Dockerfile.insecure:5
        ENV DB_PASSWORD holds a hardcoded credential.
        evidence: ENV DB_PASSWORD=<redacted 15 chars>

[CRIT] DF-005  Remote script piped into a shell
        at examples/Dockerfile.insecure:12
        evidence: curl -fsSL https://get.example.com/root.sh | sh

[HIGH] DF-012  SSH server installed in the image
        at examples/Dockerfile.insecure:11
        evidence: SSH server installed: openssh-server
...
--------------------------------------------------------------------
Findings: 17  (critical: 2, high: 5, medium: 7, low: 3, info: 0)
Sources scanned: 1
Worst severity: critical
```

## Table of contents

- [Why](#why)
- [What it checks](#what-it-checks)
- [Installation](#installation)
- [Usage](#usage)
- [Exit codes and CI integration](#exit-codes-and-ci-integration)
- [Report formats](#report-formats)
- [Silencing a rule](#silencing-a-rule)
- [Host mode: auditing a running daemon](#host-mode-auditing-a-running-daemon)
- [Architecture](#architecture)
- [Tests](#tests)
- [Security of the scanner itself](#security-of-the-scanner-itself)
- [Contributing](#contributing)
- [License](#license)

## Why

Container scanners that look at deployed images answer "what is vulnerable
inside the image?". This tool answers the complementary question: **"is this
configuration safe in the first place?"**. Both are needed, and the
configuration part is the one a reviewer can act on during code review:

* a Dockerfile is reviewed once and used thousands of times, so a hardcoded
  secret or a `chmod 777` in it leaks or weakens every deployment;
* `privileged: true` and a bind-mounted `/var/run/docker.sock` are one-line
  changes that turn a container compromise into a host compromise;
* a `daemon.json` that listens on `tcp://0.0.0.0:2375` hands a root-equivalent
  API to anyone who can reach the port;
* the container that actually runs can be far more permissive than the
  Dockerfile it was built from.

Everything is checked locally, from files, in a fraction of a second — so the
tool fits in a pre-commit hook and in a CI job.

## What it checks

61 rules, split in four families. The complete, generated table with every
description and remediation is in **[docs/RULES.md](docs/RULES.md)**; the same
catalog is available from the command line with `--list-rules`.

| Family | Rules | Examples |
| --- | --- | --- |
| `DF-` Dockerfile / image build | 15 | root user, unpinned base image, `ADD` from a URL, `curl \| sh`, secrets in `ENV`/`ARG`, `chmod 777`, SSH server in the image, unpinned packages, shell-form `CMD` |
| `CP-` Docker Compose | 16 | `privileged`, Docker socket mount, host/PID/IPC namespaces, dangerous `cap_add`, disabled seccomp/AppArmor, mounted `/`, literal secrets in the environment, database port published on `0.0.0.0`, no limits, no healthcheck, mutable image |
| `DM-` Docker daemon | 13 | remote API without TLS, `insecure-registries`, no `userns-remap`, inter-container communication, no authorization plugin, unrotated logs, unlimited ulimits, credentials in `daemon.json` |
| `CT-` running containers | 17 | privileged container, Docker socket, host namespaces, root user, writable rootfs, added capabilities, unconfined seccomp, literal secrets in `Config.Env`, exposed devices, sensitive bind mounts |

Every finding carries a severity (`critical`, `high`, `medium`, `low`), the file
or object it was found in, the observed value, and the remediation.

## Installation

The tool is a plain Python package. It has a single runtime dependency
(`PyYAML`) and works on Python 3.9+.

```bash
git clone https://github.com/Believe-sec-io/docker-security-scanner.git
cd docker-security-scanner

# Run it straight from the checkout
python main.py --help

# ... or install it (a virtual environment is recommended)
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e .
docker-security-scanner --version
```

Docker image (multi-stage, non-root, no daemon socket):

```bash
docker build -t dss .
docker run --rm -v "$PWD:/work:ro" dss /work --format console --no-color
```

## Usage

```bash
# One file (the kind is detected from the name)
docker-security-scanner Dockerfile
docker-security-scanner docker-compose.yml
docker-security-scanner daemon.json --kind daemon
docker-security-scanner docker-inspect.json --kind container

# A whole repository, stopping at the first critical finding
docker-security-scanner . --severity medium --fail-on critical

# Several targets at once
docker-security-scanner Dockerfile docker-compose.yml infra/daemon.json

# From a pipe
cat Dockerfile | docker-security-scanner --stdin --kind dockerfile
docker inspect web | docker-security-scanner --stdin --kind container
docker info --format '{{json .}}' | docker-security-scanner --stdin --kind info

# What can this tool detect, and how do I silence it?
docker-security-scanner --list-rules
docker-security-scanner --list-rules --format json | jq '.[].id'
```

`docker-security-scanner --help` documents every option.

## Exit codes and CI integration

| Exit code | Meaning |
| --- | --- |
| `0` | no finding at or above `--fail-on` (clean, or below your threshold) |
| `1` | at least one finding at or above `--fail-on` |
| `2` | the command line could not be understood (unknown option, unknown rule in `--ignore`) |
| `3` | the scan could not be completed (missing file, unreadable target, …) |

`--fail-on` makes the threshold explicit: `high` (default) fails a build on
`critical` and `high`, `critical` only on a proven host-compromise finding, and
`none` never fails — useful when you only want a report.

### GitHub Actions

```yaml
name: Docker configuration

on: [push, pull_request]

jobs:
  hardening:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - name: Audit the Docker configuration
        run: python main.py . --no-color --fail-on high --format sarif --output dss.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: dss.sarif
```

### GitLab CI

```yaml
docker-hardening:
  image: python:3.12-slim
  script:
    - pip install -r requirements.txt
    - python main.py . --no-color --format json --output dss.json --fail-on critical
  artifacts:
    when: always
    paths: [dss.json]
```

### pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: docker-security-scanner
        name: docker-security-scanner
        entry: python main.py
        language: system
        files: (Dockerfile|compose.*\.ya?ml|daemon\.json)$
        args: ["--fail-on", "high", "--no-color"]
```

## Report formats

| `--format` | Use case |
| --- | --- |
| `console` | interactive run: severity tag, location, message, evidence (add `--show-remediation` for the fix) |
| `json` | scripting, dashboards, storing a baseline; stable keys and sorted findings |
| `markdown` | pull-request comment: summary line, one table row per finding, collapsed details |
| `sarif` | the code-scanning tab of GitHub/GitLab/Azure DevOps (`SARIF 2.1.0`) |

Console colour is enabled only on a terminal and only when the report is not
written to a file; `--no-color` forces it off, which is what CI needs.

## Silencing a rule

```bash
# One rule, or several (repeatable and comma separated)
docker-security-scanner . --ignore DF-014
docker-security-scanner . --ignore DF-014,CP-015 --ignore CT-014

# Only report from a given severity upwards
docker-security-scanner . --severity medium

# Find the identifier of the rule you want to silence
docker-security-scanner --list-rules --format json | jq '.[] | {id, title, severity}'
```

An unknown identifier in `--ignore` is an error (exit code `2`) rather than a
silent no-op: a typo must never look like a clean scan.

## Host mode: auditing a running daemon

`daemon.json` is not the whole story: a daemon started from systemd flags can be
insecure even with an empty file. Export the effective configuration of the host
and scan that:

```bash
docker info --format '{{json .}}' > docker-info.json
docker-security-scanner docker-info.json --kind info   # or --stdin --kind info
```

Host mode only reports what `docker info` can actually prove (insecure
registries, TLS/API exposure through the flags, `live-restore`, inter-container
communication, logging driver rotation, authorization plugins, `userns-remap`
and `no-new-privileges` from `SecurityOptions`). A field the command does not
expose is never turned into a finding, because absence of evidence is not
evidence of a misconfiguration.

For the full picture, scan the file **and** the running state:

```bash
docker-security-scanner /etc/docker/daemon.json docker-info.json
```

## Architecture

```
main.py                     entry point (python main.py ...)
conftest.py                 puts the repository on sys.path for pytest
src/
  models.py                 Severity, Location, Finding, ScanResult
  rules.py                  the 61-rule catalog (metadata: severity, CIS/OWASP reference, fix)
  constants.py              shared reference data (sensitive ports/paths, dangerous capabilities)
  secrets.py                credential heuristics; every value is redacted before it is reported
  parsers.py                Dockerfile tokenizer, YAML/JSON loading, value coercion
  base.py                   rule filter (--ignore/--severity), Finding factory, de-duplication
  dockerfile_scanner.py     DF- rules  —  Dockerfile instructions
  compose_scanner.py        CP- rules  —  Compose services
  daemon_scanner.py         DM- rules  —  daemon.json, and host mode (docker info)
  container_scanner.py      CT- rules  —  docker inspect output
  reporters.py              console, JSON, Markdown, SARIF renderers
  scanner.py                kind detection, directory walk, dispatch to the scanners
  cli.py                    argument parsing, exit codes, --list-rules
  logger_config.py          logging to stderr (stdout stays reserved for the report)
tests/                      370 tests: one file per module, one test per rule
examples/                   hardened and insecure samples, locked by tests/test_examples.py
docs/RULES.md               generated rule catalog
```

The design keeps four things separate, which is what makes the tool easy to
extend and to trust:

1. **The catalog** (`rules.py`) holds the knowledge: an identifier, a severity,
   a description, a remediation and a reference. Nothing else.
2. **The scanners** hold the detection logic. They never invent a message or a
   fix: they observe a value and ask the base class to build the finding, so a
   rule can never be reported without its remediation.
3. **The renderers** are pure functions of a `ScanResult`. A new output format
   is one function, and the tests assert that every renderer survives an empty
   result.
4. **The CLI** only parses arguments, aggregates results and translates them
   into an exit code.

Adding a rule therefore means: add one `Rule(...)` to the catalog, add the check
that emits it, and add a test (the example files are the integration test).

## Tests

```bash
pip install -r requirements-dev.txt

python -m pytest                                   # everything
python -m pytest --cov=src --cov-report=term-missing
python -m pytest tests/test_dockerfile_scanner.py -v
python -m pytest -k "cp009 or ct016"
```

The suite is organised as a specification: **one test per rule** (both the
positive case and the "no false positive" case), one file per module, plus
integration tests that scan the samples in `examples/` in both directions. The
CI workflow runs it on Linux and Windows with Python 3.9, 3.12 and 3.13.

## Security of the scanner itself

* It never talks to the Docker daemon and needs no privileges: it reads files,
  or whatever you pipe into it.
* `yaml.safe_load` is used everywhere, so scanning a hostile Compose file cannot
  execute code or instantiate a Python object.
* Files are read with a size limit (4 MiB) and `.git`, `node_modules`,
  `__pycache__`, virtual environments and build directories are skipped.
* Secrets are **never** echoed back. A finding reports the variable name and the
  length of the value (`<redacted 15 chars>`), so a scan report can safely be
  attached to a ticket, a pull request or a CI log.
* It is a static analyser: it does not modify, pull, build or run anything.

## Contributing

1. Fork the repository and create a branch (`feat/cp-017-something`).
2. Add the rule to `src/rules.py`, its check to the matching scanner, and tests
   (`positive` + `no false positive`) in `tests/`.
3. Run `python -m pytest`, then check that the build of the project itself is
   still clean: `python main.py Dockerfile --no-color --fail-on low` (the files
   under `examples/` are *meant* to be reported — they are the demo material).
4. Regenerate the catalog if you added a rule:
   `python main.py --list-rules --format markdown --output docs/RULES.md`.
5. Open a pull request that explains **what the rule protects against** and why
   the severity is the one you chose.

Style: type hints on every public function, docstrings that explain the *why*,
no dependency beyond PyYAML, and no rule without a remediation.

## License

[MIT](LICENSE) © 2026 Believe. The rule descriptions are informed by the public
[CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) and the
[OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html);
each finding carries its reference so that a reviewer can go back to the source.

