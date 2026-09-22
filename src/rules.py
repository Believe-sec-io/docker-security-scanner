"""Machine-readable catalog of every security rule implemented by the scanner.

Rule identifiers are stable and are used in every report format (console, JSON,
Markdown, SARIF) as well as with the ``--ignore`` CLI option. They are grouped
by the surface they audit:

* ``DF-`` Dockerfile / image build instructions
* ``CP-`` docker-compose service definitions
* ``DM-`` Docker daemon configuration (``daemon.json``)
* ``CT-`` running container configuration (``docker inspect`` output)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .models import Category, Severity

_CIS_IMAGE = "CIS Docker Benchmark - 4. Container Images and Build File"
_CIS_RUNTIME = "CIS Docker Benchmark - 5. Container Runtime"
_CIS_DAEMON = "CIS Docker Benchmark - 2. Docker Daemon Configuration"
_OWASP = "OWASP Docker Security Cheat Sheet"
_DOCKER_DOCS = "https://docs.docker.com/engine/security/"


@dataclass(frozen=True)
class Rule:
    """Static metadata describing a single check."""

    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    reference: str = _CIS_IMAGE


_RULES: Tuple[Rule, ...] = (
    # ------------------------------------------------------------------ build
    Rule(
        "DF-001",
        "Container runs as root",
        Severity.HIGH,
        Category.DOCKERFILE,
        "The Dockerfile never contains a USER instruction, so the container process "
        "runs as root (UID 0). Any escape from the container namespace therefore "
        "lands on the host with root privileges.",
        "Create a dedicated unprivileged account and switch to it, for example "
        "`RUN adduser --system --uid 10001 app` followed by `USER 10001`.",
    ),
    Rule(
        "DF-002",
        "Root user set explicitly",
        Severity.HIGH,
        Category.DOCKERFILE,
        "The image explicitly sets `USER root` (or UID 0), which keeps the root "
        "privileges granted by the base image.",
        "Switch to a non-root UID before CMD/ENTRYPOINT, unless the image is a "
        "documented root-only base that is always consumed with `--user`.",
    ),
    Rule(
        "DF-003",
        "Base image is not pinned",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "FROM uses `latest`, no tag at all or a mutable tag. Builds are not "
        "reproducible and a compromised or replaced upstream tag is consumed "
        "silently on the next build.",
        "Pin the base image to an immutable digest, "
        "e.g. `FROM alpine:3.20@sha256:<digest>`.",
    ),
    Rule(
        "DF-004",
        "ADD fetches a remote URL",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "`ADD <url>` downloads an archive from the network without any integrity "
        "verification and can silently unpack it into the image.",
        "Use COPY for local files. When downloading, prefer curl/wget plus an "
        "explicit checksum check so that a tampered artifact fails the build.",
    ),
    Rule(
        "DF-005",
        "Remote script piped into a shell",
        Severity.HIGH,
        Category.DOCKERFILE,
        "A remote script is piped straight into a shell (`curl ... | sh`), which "
        "executes whatever the remote server returns at build time. Nice for "
        "convenience, terrible for supply-chain integrity.",
        "Download the script to a file, verify its checksum or GPG signature, "
        "then execute the verified file.",
    ),
    Rule(
        "DF-006",
        "Hardcoded secret in image",
        Severity.CRITICAL,
        Category.DOCKERFILE,
        "A credential-looking key is given a literal value through ENV, ARG or "
        "LABEL. It is stored in the image metadata and in the build history, so "
        "anyone who can pull the image can read it.",
        "Inject secrets at run time (env_file, orchestrator secrets) or use "
        "BuildKit `RUN --mount=type=secret` for build-time secrets.",
    ),
    Rule(
        "DF-007",
        "World-writable permissions",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "`chmod 777` (or 666) makes the target writable by every user in the "
        "container, so any compromised process can replace binaries or config.",
        "Grant the least privilege that works (750 for directories, 640 for "
        "files) and `chown` the target to the application user.",
    ),
    Rule(
        "DF-008",
        "Package manager cache not cleaned",
        Severity.LOW,
        Category.DOCKERFILE,
        "apt/apk metadata is left behind in the layer, which inflates the image "
        "and keeps the whole package index available to a compromised process.",
        "Clean up in the same RUN layer: `&& rm -rf /var/lib/apt/lists/*` for "
        "Debian/Ubuntu, `&& rm -rf /var/cache/apk/*` for Alpine.",
    ),
    Rule(
        "DF-009",
        "sudo used inside the image",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "sudo is installed or invoked inside the container. It gives any user in "
        "the image a path to root, which defeats the point of dropping privileges.",
        "Remove sudo from the image and replace it with an explicit USER plus "
        "correct file ownership.",
    ),
    Rule(
        "DF-010",
        "Sensitive port exposed",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "EXPOSE documents a port that should stay on an internal network "
        "(SSH, databases, caches, the Docker API). It only documents the intent, "
        "but it invites publishing the port to the outside world.",
        "Do not expose management or datastore ports. Publish only what has to be "
        "reachable, and bind it to 127.0.0.1 when it is a local integration.",
    ),
    Rule(
        "DF-011",
        "No HEALTHCHECK defined",
        Severity.LOW,
        Category.DOCKERFILE,
        "The image declares no HEALTHCHECK, so an orchestrator cannot tell a "
        "hung container from a healthy one and will keep routing traffic to a "
        "process that stopped serving.",
        "Add a HEALTHCHECK that exercises the real dependency, for example "
        "`HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:8080/health || exit 1`.",
    ),
    Rule(
        "DF-012",
        "SSH server installed in the image",
        Severity.HIGH,
        Category.DOCKERFILE,
        "An SSH daemon is installed inside the image. A container is not a "
        "virtual machine: the extra daemon widens the attack surface, needs "
        "credentials baked into the image and usually runs with elevated "
        "privileges.",
        "Drop the SSH server and use `docker exec` (or `kubectl exec`) for "
        "interactive access.",
    ),
    Rule(
        "DF-013",
        "Sensitive files copied into the image",
        Severity.HIGH,
        Category.DOCKERFILE,
        "COPY/ADD pulls credential material (`.env`, SSH private keys, cloud "
        "credentials, `.git`) into an image layer. Layers are immutable and "
        "still recoverable after a later `RUN rm`.",
        "Exclude secrets with a `.dockerignore` file and inject them at run "
        "time via environment, secrets or a mounted volume.",
    ),
    Rule(
        "DF-014",
        "Unpinned operating system packages",
        Severity.MEDIUM,
        Category.DOCKERFILE,
        "Packages are installed without a pinned version, so each rebuild can "
        "silently pull a different (possibly compromised or breaking) release.",
        "Pin the versions and bump them deliberately, or build on a base image "
        "digest that already contains the expected versions.",
    ),
    Rule(
        "DF-015",
        "Shell-form CMD or ENTRYPOINT",
        Severity.LOW,
        Category.DOCKERFILE,
        "Shell-form CMD/ENTRYPOINT runs the command through `/bin/sh -c`, so the "
        "application is not PID 1: SIGTERM is not delivered to it and "
        "`docker stop` degenerates into SIGKILL after the grace period.",
        "Use the exec form, for example `CMD [\"python\", \"-m\", \"app\"]`.",
    ),
    # ---------------------------------------------------------------- compose
    Rule(
        "CP-001",
        "Privileged container",
        Severity.CRITICAL,
        Category.COMPOSE,
        "`privileged: true` gives the container all Linux capabilities, access "
        "to every host device and disables the usual isolation. A single "
        "container compromise becomes a host compromise.",
        "Remove `privileged: true` and grant only the capabilities the process "
        "actually needs through `cap_add`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-002",
        "Docker socket mounted into the container",
        Severity.CRITICAL,
        Category.COMPOSE,
        "`/var/run/docker.sock` is bind-mounted. Whoever controls the container "
        "can talk to the Docker API and therefore start a privileged container, "
        "read every secret on the host and take over the machine (container "
        "escape by design, not a bug).",
        "Never mount the Docker socket into an application container. Use a "
        "socket proxy with an explicit API allow-list if an integration truly "
        "needs it.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-003",
        "Host network namespace",
        Severity.HIGH,
        Category.COMPOSE,
        "`network_mode: host` removes network isolation: the container shares "
        "the host interfaces and can bind or sniff any port, including services "
        "that were only ever meant to be reachable from inside a bridge.",
        "Use a user-defined bridge network and publish only the ports that must "
        "be reachable from outside.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-004",
        "Host PID namespace",
        Severity.HIGH,
        Category.COMPOSE,
        "`pid: host` lets the container see and signal every process of the "
        "host, which makes privilege escalation and container escape "
        "considerably easier.",
        "Drop `pid: host`; use process isolation and inspect the application "
        "through its own logs and metrics.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-005",
        "Host IPC namespace",
        Severity.MEDIUM,
        Category.COMPOSE,
        "`ipc: host` shares the host System V/POSIX shared memory with the "
        "container, allowing it to read or corrupt memory segments owned by "
        "other processes.",
        "Remove `ipc: host` and use a private IPC namespace, or `ipc: service:<name>` "
        "when two containers must really share memory.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-006",
        "Dangerous capability granted",
        Severity.HIGH,
        Category.COMPOSE,
        "`cap_add` grants a capability that is effectively equivalent to root on "
        "the host (ALL, SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN, "
        "DAC_READ_SEARCH, ...). Capabilities cannot be partially trusted.",
        "Grant the narrowest capability that makes the workload work, and test "
        "with the default capability set first.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-007",
        "Mandatory access control disabled",
        Severity.HIGH,
        Category.COMPOSE,
        "`security_opt` disables seccomp or AppArmor (`seccomp:unconfined`, "
        "`apparmor:unconfined`, `label:disable`), removing the last syscall and "
        "mandatory access control layer between the container and the kernel.",
        "Keep the default seccomp profile and the distribution AppArmor profile, "
        "or ship a custom profile that only widens what the workload needs.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-008",
        "no-new-privileges not enabled",
        Severity.LOW,
        Category.COMPOSE,
        "`no-new-privileges` is missing, so setuid binaries and file capabilities "
        "inside the image can still be used to gain privileges.",
        "Add `security_opt: [no-new-privileges:true]` to the service.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-009",
        "Sensitive host path bind-mounted",
        Severity.HIGH,
        Category.COMPOSE,
        "A host directory is bind-mounted read-write with a scope far beyond the "
        "application data (the whole root filesystem, `/etc`, `/proc`, `/sys`, "
        "`/dev`, the Docker socket directory, the cloud metadata paths). The "
        "container can modify host configuration or read host secrets.",
        "Mount only the exact subdirectory the workload needs, and mount it "
        "read-only (`:ro`) whenever writes are not required.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-010",
        "Secret exposed in the service environment",
        Severity.CRITICAL,
        Category.COMPOSE,
        "A credential-looking variable holds a literal value in `environment`. "
        "Compose files live in Git, the value is visible in `docker inspect` and "
        "it is inherited by every process of the container.",
        "Use Compose `secrets` (or your orchestrator's secret store) and read the "
        "value from a file at run time.",
        _OWASP,
    ),
    Rule(
        "CP-011",
        "Sensitive port published on every interface",
        Severity.MEDIUM,
        Category.COMPOSE,
        "A management or datastore port (Docker API, SSH, PostgreSQL, MySQL, "
        "Redis, MongoDB, Elasticsearch, memcached, Kafka, ...) is published "
        "without a host address, so it listens on 0.0.0.0 and is reachable from "
        "every network the host is attached to.",
        "Remove the `ports` entry when only other services need it, or bind it to "
        "the loopback address: `\"127.0.0.1:5432:5432\"`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-012",
        "No CPU or memory limit",
        Severity.LOW,
        Category.COMPOSE,
        "The service declares no memory or CPU limit, so a runaway or "
        "compromised container can starve every other workload on the host "
        "(denial of service from the inside).",
        "Set `mem_limit`/`cpus` (or `deploy.resources.limits`) to a value that "
        "matches the real usage of the service.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-013",
        "Root filesystem is writable",
        Severity.LOW,
        Category.COMPOSE,
        "`read_only` is not enabled, so a compromised process can modify its own "
        "binaries or drop a persistence payload inside the container filesystem.",
        "Add `read_only: true` and mount the directories that must be writable "
        "(tmpfs, logs, cache) explicitly.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-014",
        "No container user defined",
        Severity.HIGH,
        Category.COMPOSE,
        "The service does not set `user`, so it inherits the user of the image. "
        "When the image has no USER instruction either, the process runs as root "
        "inside the container.",
        "Set `user: \"10001:10001\"` (or a named account) on the service and make "
        "sure the mounted volumes are owned by that UID.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-015",
        "No healthcheck defined",
        Severity.LOW,
        Category.COMPOSE,
        "The service has no healthcheck, so Compose cannot restart it when it "
        "hangs and dependencies start while the service is still unusable.",
        "Add a `healthcheck` with a real readiness endpoint and use "
        "`depends_on: condition: service_healthy`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CP-016",
        "Mutable image reference",
        Severity.MEDIUM,
        Category.COMPOSE,
        "The image is referenced with `latest`, with no tag at all or with a "
        "local build tag, so the next `docker compose pull` can silently deploy "
        "something different from what was reviewed.",
        "Pin the image by digest (`image: nginx:1.27@sha256:<digest>`).",
        _OWASP,
    ),
    # ----------------------------------------------------------------- daemon
    Rule(
        "DM-001",
        "Remote API exposed without TLS",
        Severity.CRITICAL,
        Category.DAEMON,
        "The daemon listens on a TCP socket (or TLS is explicitly disabled) so "
        "the Docker API is reachable over the network. That API is root "
        "equivalent: whoever reaches it can start a privileged container and "
        "mount the host filesystem.",
        "Keep the daemon on the Unix socket, or expose it only through an SSH "
        "tunnel / a socket proxy with client authentication.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-002",
        "Insecure registry configured",
        Severity.HIGH,
        Category.DAEMON,
        "`insecure-registries` allows image pulls over plain HTTP or with an "
        "untrusted certificate, so a network attacker can replace the image "
        "that gets deployed.",
        "Use a registry with a valid TLS certificate, or configure the internal "
        "CA in `/etc/docker/certs.d/<registry>/ca.crt` instead of disabling TLS.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-003",
        "no-new-privileges not enabled on the daemon",
        Severity.MEDIUM,
        Category.DAEMON,
        "The daemon-level `no-new-privileges` flag is not set, so containers may "
        "still gain privileges through setuid binaries or file capabilities.",
        "Set `\"no-new-privileges\": true` in `daemon.json` (startup-only "
        "restriction, but it protects every container on the host).",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-004",
        "userland-proxy enabled",
        Severity.LOW,
        Category.DAEMON,
        "The userland proxy stays enabled, which keeps an extra userspace "
        "process per published port and widens the exposed surface.",
        "Set `\"userland-proxy\": false` so published ports are handled by the "
        "kernel rules only.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-005",
        "live-restore disabled",
        Severity.LOW,
        Category.DAEMON,
        "`live-restore` is not enabled, so restarting or upgrading the daemon "
        "kills every running container (availability and forensic loss).",
        "Set `\"live-restore\": true`; containers keep running while the daemon "
        "is restarted.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-006",
        "Inter-container communication enabled",
        Severity.MEDIUM,
        Category.DAEMON,
        "Inter-container communication is not disabled on the default bridge, "
        "so a compromised container can reach every other container on the same "
        "bridge without any authentication.",
        "Set `\"icc\": false` and create explicit user-defined networks for the "
        "services that must talk to each other.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-007",
        "No authorization plugin",
        Severity.MEDIUM,
        Category.DAEMON,
        "No authorization plugin is configured, so every Linux user in the "
        "`docker` group can perform any API call, including privileged "
        "operations.",
        "Use a plugin (for example `authz-broker`) or remove users from the "
        "`docker` group and go through a controlled API gateway.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-008",
        "User namespace remapping disabled",
        Severity.MEDIUM,
        Category.DAEMON,
        "`userns-remap` is not enabled: container root is host root. A container "
        "escape therefore lands directly on the host as UID 0.",
        "Set `\"userns-remap\": \"default\"` and re-check the UID mappings of "
        "mounted volumes.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-009",
        "Container logs are not rotated",
        Severity.LOW,
        Category.DAEMON,
        "The log driver is a file-based driver without `max-size`/`max-file`, so "
        "logs grow until the host disk is full and the whole node stops.",
        "Configure rotation, for example "
        "`\"log-driver\": \"json-file\", \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}`.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-010",
        "iptables management disabled",
        Severity.MEDIUM,
        Category.DAEMON,
        "`iptables` is disabled, so Docker no longer creates the rules that "
        "isolate containers and manage published ports; another component has "
        "to do it correctly, which is rarely verified.",
        "Leave `iptables` at its default (true) unless a documented alternative "
        "firewall manager handles container networking.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-011",
        "Unlimited default ulimits",
        Severity.LOW,
        Category.DAEMON,
        "A default ulimit is set to unlimited (-1), so a fork bomb or a file "
        "descriptor leak inside any container can exhaust host resources.",
        "Set finite soft/hard values in `default-ulimits`.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-012",
        "seccomp profile disabled",
        Severity.HIGH,
        Category.DAEMON,
        "`seccomp-profile` is set to `unconfined`, which removes the daemon-wide "
        "syscall filtering that blocks many kernel exploits.",
        "Remove the setting (the built-in default profile is a good baseline) or "
        "point it to a reviewed custom profile.",
        _CIS_DAEMON,
    ),
    Rule(
        "DM-013",
        "Credential stored in the daemon configuration",
        Severity.HIGH,
        Category.DAEMON,
        "`daemon.json` contains a credential-looking value (registry password, "
        "proxy password, token). The file is world-readable on the host, is "
        "usually versioned and is copy-pasted between machines.",
        "Remove the value from `daemon.json`, reference a file that is readable "
        "only by root (`\\\"passwordFile\\\"`), or inject the credential at "
        "deploy time from a secret store.",
        _CIS_DAEMON,
    ),
    # -------------------------------------------------------------- containers
    Rule(
        "CT-001",
        "Privileged container",
        Severity.CRITICAL,
        Category.CONTAINER,
        "`HostConfig.Privileged` is true: the container owns all Linux "
        "capabilities and can talk to every device on the host. Privileged "
        "containers are documented as not containing a strong security boundary.",
        "Recreate the container without `--privileged` and add back only the "
        "specific capabilities it needs with `--cap-add`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-002",
        "Docker socket mounted into the container",
        Severity.CRITICAL,
        Category.CONTAINER,
        "`/var/run/docker.sock` is bind-mounted into a running container. The "
        "Docker API has no authorization by default, so the container can start "
        "a privileged container, read host secrets and own the machine.",
        "Remove the mount and route the integration through a socket proxy that "
        "allow-lists the API endpoints it really needs.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-003",
        "Host network namespace",
        Severity.HIGH,
        Category.CONTAINER,
        "`HostConfig.NetworkMode` is `host`, so the container has no network "
        "isolation: it can bind any host port and sniff traffic meant to be "
        "local to the machine.",
        "Recreate the container on a user-defined bridge network and publish "
        "only the required ports explicitly.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-004",
        "Host PID namespace",
        Severity.HIGH,
        Category.CONTAINER,
        "`HostConfig.PidMode` is `host`: the container sees and can signal every "
        "process on the host, including the daemon and other tenants.",
        "Recreate the container without `--pid=host`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-005",
        "Host IPC namespace",
        Severity.MEDIUM,
        Category.CONTAINER,
        "`HostConfig.IpcMode` is `host`, which shares host shared-memory "
        "segments with the container and enables cross-process attacks.",
        "Recreate the container without `--ipc=host` and use a private IPC "
        "namespace (the default).",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-006",
        "Container runs as root",
        Severity.HIGH,
        Category.CONTAINER,
        "`Config.User` is empty, `root` or UID `0`, so the main process runs as "
        "root inside the container. Combined with a kernel or namespace flaw, "
        "this is a direct path to host root.",
        "Recreate the container with `--user <uid>:<gid>` and make sure the "
        "mounted volumes are owned by that UID.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-007",
        "Writable root filesystem",
        Severity.MEDIUM,
        Category.CONTAINER,
        "`HostConfig.ReadonlyRootfs` is false, so an attacker who compromises "
        "the application can modify any file in the image, persist inside the "
        "container and replace tooling.",
        "Recreate the container with `--read-only` and mount the paths that "
        "must be writable as volumes or tmpfs.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-008",
        "Dangerous capabilities added",
        Severity.HIGH,
        Category.CONTAINER,
        "`HostConfig.CapAdd` grants capabilities such as `SYS_ADMIN`, "
        "`NET_ADMIN`, `SYS_PTRACE` or `ALL`. Several of these are equivalent to "
        "root on the host when combined with the kernel surface they expose.",
        "Drop the added capabilities and keep the default set, subtracting the "
        "ones that are not needed with `--cap-drop`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-009",
        "no-new-privileges not enabled",
        Severity.MEDIUM,
        Category.CONTAINER,
        "`no-new-privileges` is missing from `HostConfig.SecurityOpt`, so a "
        "setuid binary or a file capability inside the image can still raise "
        "the effective privileges of the process.",
        "Recreate the container with `--security-opt no-new-privileges:true`.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-010",
        "seccomp profile unconfined",
        Severity.HIGH,
        Category.CONTAINER,
        "`SecurityOpt` contains `seccomp=unconfined`: the container may call "
        "any kernel syscall, which removes the main mitigation against kernel "
        "exploits reachable from user space.",
        "Recreate the container without `--security-opt seccomp=unconfined` so "
        "the daemon's default profile applies.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-011",
        "No HEALTHCHECK defined",
        Severity.LOW,
        Category.CONTAINER,
        "`Config.Healthcheck` is null, so an orchestrator cannot distinguish a "
        "healthy container from one whose process is still running but no "
        "longer serving traffic.",
        "Recreate the container with `--health-cmd` (and `--health-interval`) "
        "or declare a HEALTHCHECK in the image.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-012",
        "Mutable image reference",
        Severity.MEDIUM,
        Category.CONTAINER,
        "`Config.Image` uses `latest`, no tag at all or a locally built tag, so "
        "restarting the container can silently run a different image than the "
        "one that was reviewed.",
        "Recreate the container from an image pinned by digest "
        "(`registry/app@sha256:<digest>`).",
        _OWASP,
    ),
    Rule(
        "CT-013",
        "Secret exposed in the container environment",
        Severity.CRITICAL,
        Category.CONTAINER,
        "`Config.Env` carries a credential-looking variable with a literal "
        "value. The value is readable by any user who can call `docker inspect` "
        "and it is inherited by every process in the container.",
        "Recreate the container with `--env-file` / orchestrator secrets, or "
        "mount the secret as a file and read it from the application.",
        _OWASP,
    ),
    Rule(
        "CT-014",
        "No CPU or memory limit",
        Severity.LOW,
        Category.CONTAINER,
        "Neither `HostConfig.Memory` nor `HostConfig.NanoCpus` is set, so a "
        "runaway or compromised container can consume every resource of the "
        "host and starve the other workloads.",
        "Recreate the container with `--memory` and `--cpus` limits.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-015",
        "Mandatory access control not confined",
        Severity.MEDIUM,
        Category.CONTAINER,
        "`HostConfig.SecurityOpt` contains no AppArmor or SELinux confinement "
        "entry, so the container is not restricted by the mandatory access "
        "control policy of the host.",
        "Recreate the container with `--security-opt apparmor=docker-default` "
        "(or a reviewed custom profile).",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-016",
        "Sensitive host path bind-mounted",
        Severity.HIGH,
        Category.CONTAINER,
        "A host path with a scope far beyond the application data (the root "
        "filesystem, `/etc`, `/proc`, `/sys`, `/dev`, the cloud metadata "
        "paths) is bind-mounted read-write into the container.",
        "Recreate the container with a narrower source path and add the `:ro` "
        "option whenever writes are not required.",
        _CIS_RUNTIME,
    ),
    Rule(
        "CT-017",
        "Host device exposed to the container",
        Severity.HIGH,
        Category.CONTAINER,
        "`HostConfig.Devices` maps one or more host devices into the container. "
        "Raw device access (disk, kernel memory, GPU management) allows "
        "tampering with the host outside of any namespace boundary.",
        "Remove the `--device` flags and use a driver or a dedicated service "
        "for the workload that needs the hardware.",
        _CIS_RUNTIME,
    ),
)


#: The full rule catalog, in declaration order.
RULES: Tuple[Rule, ...] = _RULES

#: Lookup table used by the reporters and the ``--ignore`` option.
RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in _RULES}

#: Rule identifiers in declaration order (used by the CLI help and the tests).
RULE_IDS: Tuple[str, ...] = tuple(rule.id for rule in _RULES)


def get_rule(rule_id: str) -> Rule:
    """Return the rule with ``rule_id``, raising ``KeyError`` when unknown."""
    try:
        return RULES_BY_ID[rule_id]
    except KeyError:
        raise KeyError(f"unknown rule id {rule_id!r}") from None


def rules_by_category(category: Category) -> Tuple[Rule, ...]:
    """Return every rule that applies to ``category``, in declaration order."""
    return tuple(rule for rule in _RULES if rule.category is category)


def unknown_rule_ids(rule_ids: List[str]) -> List[str]:
    """Return the identifiers of ``rule_ids`` that do not exist in the catalog.

    The comparison is case-insensitive: a user typing ``--ignore cp-002`` means
    the same thing as ``CP-002``, and the CLI validates the value with this
    helper so that a typo fails loudly instead of silently disabling nothing.
    """
    return [
        rule_id for rule_id in rule_ids if str(rule_id).strip().upper() not in RULES_BY_ID
    ]


__all__ = [
    "RULES",
    "RULES_BY_ID",
    "RULE_IDS",
    "Rule",
    "rules_by_category",
    "unknown_rule_ids",
]
