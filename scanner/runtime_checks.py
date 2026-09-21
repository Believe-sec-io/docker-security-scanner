"""Posture de securite d'un conteneur en execution, a partir de `docker inspect`.

La fonction `analyze_container()` est pure (entree = dictionnaire JSON), ce qui la
rend testable sans demon Docker. `scan_container()` sert d'enveloppe CLI.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .dockerfile_rules import SENSITIVE_PORTS
from .models import Finding
from .rules import make_finding

# Capacites Linux particulierement dangereuses
DANGEROUS_CAPS = {
    "ALL",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "NET_RAW",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "MKNOD",
    "AUDIT_CONTROL",
    "SETFCAP",
}

# Chemins de l'hote qui ne doivent jamais etre montes en ecriture
SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/var",
    "/var/run/docker.sock",
    "/var/lib/docker",
    "/root",
    "/home",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/usr",
)

LOG_DRIVERS_WITH_ROTATION = ("json-file", "local")


# --------------------------------------------------------------------------- #
#                            Acces au demon Docker                            #
# --------------------------------------------------------------------------- #

def docker_available() -> bool:
    """Vrai si le binaire docker est present sur la machine."""
    return shutil.which("docker") is not None


def run_docker(args: Sequence[str], timeout: int = 60) -> Tuple[int, str, str]:
    """Execute une commande docker et retourne (code, sortie, erreur)."""
    try:
        result = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError:
        return 127, "", "docker introuvable dans le PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"delai depasse ({timeout}s)"


def inspect_container(name: str) -> Dict[str, Any]:
    """Retourne le JSON `docker inspect` d'un conteneur."""
    code, out, err = run_docker(["inspect", name])
    if code != 0:
        raise RuntimeError(f"docker inspect a echoue pour « {name} » : {err.strip() or code}")
    data = json.loads(out)
    if not data:
        raise RuntimeError(f"Aucune donnee d'inspection pour « {name} »")
    return data[0]


def save_image(name: str, destination: str, timeout: int = 300) -> None:
    """Exporte une image locale en archive tar (`docker save`)."""
    code, _out, err = run_docker(["save", "-o", destination, name], timeout=timeout)
    if code != 0:
        raise RuntimeError(f"docker save a echoue pour « {name} » : {err.strip() or code}")


# --------------------------------------------------------------------------- #
#                            Regles de posture                                #
# --------------------------------------------------------------------------- #

def _sources_of_mount(mount: Dict[str, Any]) -> str:
    """Chemin hote d'un montage (Source ou Name pour les volumes nommes)."""
    return str(mount.get("Source") or mount.get("Name") or "")


def _check_privileged(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-001 : conteneur privilegie."""
    if not host.get("Privileged"):
        return []
    return [
        make_finding(
            "DS-RT-001",
            "Le conteneur est lance en mode privilegie : il dispose des capacites de l'hote et peut s'en echapper.",
            target,
            "HostConfig.Privileged = true",
        )
    ]


def _check_namespaces(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-002 : partage de namespaces de l'hote."""
    findings: List[Finding] = []
    for key, label in (("NetworkMode", "reseau"), ("PidMode", "PID"), ("IpcMode", "IPC"), ("UTSMode", "UTS")):
        value = str(host.get(key, "") or "")
        if value in ("host", "container"):
            findings.append(
                make_finding(
                    "DS-RT-002",
                    f"Partage du namespace {label} avec l'hote ({key} = {value}) : isolation contournee.",
                    target,
                    f"HostConfig.{key} = {value}",
                )
            )
    return findings


def _check_capabilities(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-003 : capacites Linux dangereuses ajoutees."""
    added = {str(cap).upper() for cap in (host.get("CapAdd") or [])}
    dangerous = sorted(added & DANGEROUS_CAPS)
    if not dangerous:
        return []
    return [
        make_finding(
            "DS-RT-003",
            f"Capacites Linux dangereuses ajoutees : {', '.join(dangerous)}.",
            target,
            "HostConfig.CapAdd = " + ", ".join(dangerous),
        )
    ]


def _check_resource_limits(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-004 : absence de limites de ressources."""
    memory = int(host.get("Memory") or 0)
    cpus = int(host.get("NanoCpus") or 0)
    quota = int(host.get("CpuQuota") or 0)
    if memory > 0 and (cpus > 0 or quota > 0):
        return []
    missing = []
    if memory <= 0:
        missing.append("memoire")
    if cpus <= 0 and quota <= 0:
        missing.append("CPU")
    return [
        make_finding(
            "DS-RT-004",
            f"Aucune limite de ressources definie ({', '.join(missing)}) : un conteneur peut affamer l'hote.",
            target,
            f"Memory = {memory}, NanoCpus = {cpus}",
        )
    ]


def _check_docker_socket(mounts: Sequence[Dict[str, Any]], target: str) -> List[Finding]:
    """DS-RT-005 : socket Docker monte dans le conteneur."""
    for mount in mounts:
        source = _sources_of_mount(mount)
        if "docker.sock" in source:
            return [
                make_finding(
                    "DS-RT-005",
                    "Le socket Docker est monte dans le conteneur : controle total du demon, evasion d'isolation.",
                    target,
                    f"mount {source} -> {mount.get('Destination', '')}",
                )
            ]
    return []


def _check_user(data: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-006 : conteneur execute en root."""
    user = str((data.get("Config") or {}).get("User", "") or "").strip()
    if user and user.split(":")[0].lower() not in ("root", "0"):
        return []
    return [
        make_finding(
            "DS-RT-006",
            "Le conteneur s'execute en root (Config.User vide ou root).",
            target,
            f"Config.User = {user or '<vide>'}",
        )
    ]


def _check_readonly_rootfs(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-007 : systeme de fichiers racine inscriptible."""
    if host.get("ReadonlyRootfs"):
        return []
    return [
        make_finding(
            "DS-RT-007",
            "Le systeme de fichiers racine n'est pas en lecture seule (option --read-only).",
            target,
            "HostConfig.ReadonlyRootfs = false",
        )
    ]


def _check_security_profiles(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-008 : aucun profil seccomp/AppArmor actif."""
    options = [str(option).lower() for option in (host.get("SecurityOpt") or [])]
    applied = any(option.startswith(("seccomp=", "apparmor=", "label=")) for option in options)
    if applied and "unconfined" not in " ".join(options):
        return []
    joined = " ".join(options)
    return [
        make_finding(
            "DS-RT-008",
            "Aucun profil seccomp/AppArmor actif (ou profil « unconfined ») : appels systeme non filtres.",
            target,
            "HostConfig.SecurityOpt = " + (joined or "<vide>"),
        )
    ]


def _check_mounts(mounts: Sequence[Dict[str, Any]], target: str) -> List[Finding]:
    """DS-RT-009 : chemins sensibles de l'hote montes en ecriture."""
    findings: List[Finding] = []
    for mount in mounts:
        source = _sources_of_mount(mount)
        if not source.startswith("/") or mount.get("RW") is False:
            continue
        normalized = source.rstrip("/") or "/"
        if any(
            normalized == path.rstrip("/") or normalized.startswith(path.rstrip("/") + "/")
            for path in SENSITIVE_HOST_PATHS
        ):
            findings.append(
                make_finding(
                    "DS-RT-009",
                    f"Chemin sensible de l'hote monte en lecture-ecriture : {source}.",
                    target,
                    f"mount {source} -> {mount.get('Destination', '')}",
                )
            )
    return findings


def _check_published_ports(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-010 : port sensible publie sur toutes les interfaces."""
    findings: List[Finding] = []
    bindings = host.get("PortBindings") or {}
    for container_port, entries in bindings.items():
        port = str(container_port).split("/")[0]
        if not port.isdigit():
            continue
        service = SENSITIVE_PORTS.get(int(port))
        if not service:
            continue
        for entry in entries or []:
            host_ip = str((entry or {}).get("HostIp", "") or "")
            host_port = (entry or {}).get("HostPort", "")
            if host_ip in ("", "0.0.0.0", "::"):
                findings.append(
                    make_finding(
                        "DS-RT-010",
                        f"Port sensible {port} ({service}) publie sur toutes les interfaces (0.0.0.0).",
                        target,
                        f"PortBindings {container_port} -> {host_ip or '*'}:{host_port}",
                    )
                )
    return findings


# --- fin des controles de ports ---


def _check_restart_and_healthcheck(data: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-011 : redemarrage automatique sans healthcheck."""
    policy = str(((data.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name", "") or "")
    if policy not in ("always", "unless-stopped"):
        return []
    if (data.get("Config") or {}).get("Healthcheck"):
        return []
    return [
        make_finding(
            "DS-RT-011",
            f"Politique de redemarrage « {policy} » sans HEALTHCHECK : boucle de redemarrage silencieuse possible.",
            target,
            f"RestartPolicy = {policy}",
        )
    ]


def _check_log_rotation(host: Dict[str, Any], target: str) -> List[Finding]:
    """DS-RT-012 : absence de rotation des journaux."""
    log_config = host.get("LogConfig") or {}
    driver = str(log_config.get("Type", "") or "")
    options = {str(key).lower(): str(value) for key, value in (log_config.get("Config") or {}).items()}
    if not driver or "max-size" in options:
        return []
    return [
        make_finding(
            "DS-RT-012",
            f"Pilote de journalisation « {driver} » sans « max-size » : les journaux peuvent saturer le disque de l'hote.",
            target,
            f"LogConfig = {driver}",
        )
    ]


# --------------------------------------------------------------------------- #
#                              API publique                                   #
# --------------------------------------------------------------------------- #

def analyze_container(data: Dict[str, Any], target: str = "") -> List[Finding]:
    """Analyse un objet `docker inspect` (un conteneur) et retourne les constats."""
    host = data.get("HostConfig") or {}
    mounts = data.get("Mounts") or []
    label = target or str(data.get("Name", "") or data.get("Id", ""))[:20] or "container"
    findings: List[Finding] = []
    findings.extend(_check_privileged(host, label))
    findings.extend(_check_namespaces(host, label))
    findings.extend(_check_capabilities(host, label))
    findings.extend(_check_resource_limits(host, label))
    findings.extend(_check_docker_socket(mounts, label))
    findings.extend(_check_user(data, label))
    findings.extend(_check_readonly_rootfs(host, label))
    findings.extend(_check_security_profiles(host, label))
    findings.extend(_check_mounts(mounts, label))
    findings.extend(_check_published_ports(host, label))
    findings.extend(_check_restart_and_healthcheck(data, label))
    findings.extend(_check_log_rotation(host, label))
    return findings


def container_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """Resume lisible d'un conteneur inspecte."""
    host = data.get("HostConfig") or {}
    state = data.get("State") or {}
    config = data.get("Config") or {}
    return {
        "name": str(data.get("Name", "") or "").lstrip("/"),
        "image": str(config.get("Image", "") or ""),
        "created": str(data.get("Created", "") or ""),
        "status": str(state.get("Status", "") or ""),
        "restart_count": state.get("RestartCount", 0),
        "privileged": bool(host.get("Privileged")),
        "network_mode": str(host.get("NetworkMode", "") or ""),
        "capabilities_added": list(host.get("CapAdd") or []),
        "read_only_rootfs": bool(host.get("ReadonlyRootfs")),
        "user": str(config.get("User", "") or "") or "root (par defaut)",
        "memory_limit": int(host.get("Memory") or 0),
        "cpu_limit": int(host.get("NanoCpus") or 0),
        "mounts": len(data.get("Mounts") or []),
        "restart_policy": str((host.get("RestartPolicy") or {}).get("Name", "") or ""),
    }


def scan_container(name: str) -> Tuple[List[Finding], Dict[str, Any]]:
    """Inspecte un conteneur en cours d'execution : (constats, metadonnees)."""
    data = inspect_container(name)
    return analyze_container(data, target=str(data.get("Name", "") or name).lstrip("/")), container_metadata(data)


