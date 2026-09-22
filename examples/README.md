# Example configurations

Every file here is scanned by the test suite (`tests/test_examples.py`), which
locks the behaviour of the rule engine in both directions:

* the **hardened** samples must stay clean — they are the reference of how to
  configure a Docker build, a Compose project, the daemon and a container;
* the **insecure** samples must keep reporting the rules they illustrate — a
  rule that silently stops working is a regression.

| File | Kind | Expected result |
| --- | --- | --- |
| `Dockerfile.insecure` | Dockerfile | 15 rules, `DF-002` … `DF-015`, 2 critical |
| `Dockerfile.secure` | Dockerfile | no finding |
| `docker-compose.insecure.yml` | Compose | all 16 `CP-` rules, 3 critical |
| `docker-compose.secure.yml` | Compose | no finding |
| `daemon.json.insecure` | daemon | all 13 `DM-` rules, 1 critical |
| `daemon.json.secure` | daemon | no finding |
| `docker-inspect.insecure.json` | containers | all 17 `CT-` rules, 3 critical |
| `docker-inspect.secure.json` | containers | no finding |
| `docker-info.insecure.json` | host mode | 8 `DM-` rules that `docker info` can prove |

## Run the scanner on them

```bash
# One file, human readable report
python main.py examples/Dockerfile.insecure --no-color

# The whole folder, every format
python main.py examples --format console  --no-color
python main.py examples --format json      --output report.json
python main.py examples --format markdown  --output report.md
python main.py examples --format sarif     --output dss.sarif

# A pipeline that must fail on a critical finding
python main.py examples/docker-compose.insecure.yml --fail-on critical

# The same scan the CI job runs, and which must stay clean
python main.py examples/Dockerfile.secure --fail-on low
```

## Reproducing the input files

The container and daemon samples are snapshots of real commands. To produce your
own versions:

```bash
# Running containers
docker inspect $(docker ps -q) > docker-inspect.json

# The daemon flags of the running host
docker info --format '{{json .}}' > docker-info.json

# The daemon configuration file
sudo cat /etc/docker/daemon.json > daemon.json
```

> The insecure samples contain deliberately fake credentials (`hunter2-hunter2`,
> `ci-token-9f2b41`, ...). The scanner never prints a secret value back: it
> reports the variable name and its length, so the reports are safe to attach to
> a ticket even when a real credential is involved.
