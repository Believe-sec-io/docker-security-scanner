"""Analyse statique des Dockerfiles (inspire du CIS Docker Benchmark et des
regles DevSecOps courantes).

Aucune image n'est telechargee : tout est deduit du contenu du fichier.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from . import secrets
from .models import Finding
from .rules import make_finding

# Ports sensibles : exposer ces services augmente fortement la surface d'attaque.
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    2375: "Docker API (non chiffree)",
    2376: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Images de base en fin de vie (heuristique, a maintenir manuellement).
# Motif -> raison affichee dans le constat.
EOL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)ubuntu:(12\.04|14\.04|16\.04|18\.04|20\.04|21\.04|21\.10|22\.10|23\.04|23\.10)"), "Ubuntu arrive en fin de support",
    ),
    (re.compile(r"(?i)debian:(7|8|9|10)\b"), "Debian ancienne version (fin de support)"),
    (re.compile(r"(?i)centos:(6|7|8)\b"), "CentOS en fin de vie"),
    (re.compile(r"(?i)alpine:3\.(0|1|2|3|4|5|6|7|8|9|1[0-6])(?![0-9])"), "Alpine ancienne branche"),
    (re.compile(r"(?i)node:(0|4|6|8|10|12|14)\b"), "Node.js en fin de support"),
    (re.compile(r"(?i)python:2"), "Python 2 est en fin de vie"),
    (re.compile(r"(?i)python:3\.(5|6|7|8)\b"), "Python 3.5-3.8 en fin de support"),
    (re.compile(r"(?i)php:7\.[0-3]\b"), "PHP 7.0-7.3 en fin de support"),
    (re.compile(r"(?i)ruby:2\.[0-4]\b"), "Ruby 2.0-2.4 en fin de support"),
    (re.compile(r"(?i)openjdk:(6|7|8)\b"), "OpenJDK 6-8 en fin de support"),
]

PIPE_TO_SHELL = re.compile(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b")
WORLD_WRITABLE = re.compile(r"(?i)chmod\s+(-R\s+)?0?777")
SUDO_USAGE = re.compile(r"(?i)(^|[;&|]\s*)sudo\s")
PINNED_PIP = re.compile(r"(?i)\bpip3?\s+install\b")
PINNED_NPM = re.compile(r"(?i)\bnpm\s+(install|i)\s")
DEPRECATION_MESSAGE = "instruction historique, remplacee par LABEL"


@dataclass
class Instruction:
    """Une instruction Dockerfile normalisee (continuations fusionnees)."""

    keyword: str
    arguments: str
    line: int

    @property
    def text(self) -> str:
        return f"{self.keyword} {self.arguments}".strip()


def _logical_lines(text: str) -> Iterator[Tuple[int, str]]:
    """Fusionne les continuations de ligne et ignore commentaires / lignes vides."""
    current = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not current:
            if not stripped or stripped.startswith("#"):
                continue
            start = number
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        yield start, current
        current = ""
    if current:
        yield start, current


def parse_dockerfile(text: str) -> List[Instruction]:
    """Transforme le contenu d'un Dockerfile en liste d'instructions."""
    instructions: List[Instruction] = []
    for line, content in _logical_lines(text):
        keyword, _, arguments = content.partition(" ")
        instructions.append(Instruction(keyword.upper(), arguments.strip(), line))
    return instructions


def read_dockerfile(path: str) -> str:
    """Lit un Dockerfile en UTF-8 (remplacement des octets invalides)."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()



# --------------------------------------------------------------------------- #
#                              Regles Dockerfile                              #
# --------------------------------------------------------------------------- #

DOCKERIGNORE_REQUIRED_ENTRIES = (
    (".git", "depot Git complet"),
    (".env", "variables d'environnement"),
    ("id_rsa", "cle privee SSH"),
    ("*.pem", "certificat ou cle"),
    ("*.key", "cle privee"),
    ("node_modules", "dependances locales"),
)


def _base_image_reference(from_instruction: Instruction) -> str:
    """Retourne la reference d'image d'une instruction FROM (sans le stage)."""
    arguments = from_instruction.arguments
    return arguments.split(" AS ")[0].split(" as ")[0].strip()


def _is_tag_pinned(reference: str) -> bool:
    """Vrai si la reference est epinglee par digest ou par tag explicite."""
    if "@sha256:" in reference:
        return True
    image = reference.split("/")[-1]
    if image.startswith("$"):  # reference parametree par un ARG
        return True
    if ":" not in image:
        return False
    return image.rsplit(":", 1)[1].lower() != "latest"


def _check_base_images(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-001 (tag mutable) et DS-DF-015 (image en fin de vie)."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword != "FROM":
            continue
        reference = _base_image_reference(instruction)
        if not reference or reference == "scratch" or reference.startswith("$"):
            continue
        if not _is_tag_pinned(reference):
            findings.append(
                make_finding(
                    "DS-DF-001",
                    f"L'image de base « {reference} » n'est pas epinglee (tag absent ou « latest »).",
                    target,
                    f"L{instruction.line}: FROM {reference}",
                )
            )
        for pattern, reason in EOL_PATTERNS:
            if pattern.search(reference):
                findings.append(
                    make_finding(
                        "DS-DF-015",
                        f"Image de base « {reference} » : {reason}.",
                        target,
                        f"L{instruction.line}: FROM {reference}",
                    )
                )
                break
    return findings


def _check_user(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-002 : conteneur qui s'execute en root."""
    last_from: Optional[Instruction] = None
    users: List[Instruction] = []
    for instruction in instructions:
        if instruction.keyword == "FROM":
            last_from = instruction
            users = []
        elif instruction.keyword == "USER":
            users.append(instruction)

    if users:
        last_user = users[-1].arguments.split(":")[0].strip().lower()
        if last_user not in ("root", "0", ""):
            return []
        evidence = f"L{users[-1].line}: USER {users[-1].arguments}"
    else:
        evidence = "aucune instruction USER dans l'image"
    return [
        make_finding(
            "DS-DF-002",
            "Le conteneur s'execute en root (aucune instruction USER, ou USER root).",
            target,
            evidence,
        )
    ]


def _check_healthcheck(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-003 : absence de HEALTHCHECK."""
    if any(i.keyword == "HEALTHCHECK" for i in instructions):
        return []
    return [
        make_finding(
            "DS-DF-003",
            "Aucun HEALTHCHECK declare : un conteneur bloque peut rester considere comme sain.",
            target,
        )
    ]


def _check_run_commands(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-004/005/006/009/010/011/012 : analyse des commandes RUN."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword != "RUN":
            continue
        command = instruction.arguments
        lowered = command.lower()
        evidence = f"L{instruction.line}: {command[:160]}"

        if ("apt-get install" in lowered or "apt install " in lowered) and "--no-install-recommends" not in lowered:
            findings.append(
                make_finding(
                    "DS-DF-004",
                    "Installation de paquets sans « --no-install-recommends » : paquets inutiles ajoutes a l'image.",
                    target,
                    evidence,
                )
            )
        if ("apt-get install" in lowered or "apt install " in lowered) and "rm -rf /var/lib/apt/lists" not in lowered:
            findings.append(
                make_finding(
                    "DS-DF-005",
                    "Le cache APT n'est pas nettoye apres l'installation.",
                    target,
                    evidence,
                )
            )
        if "apk add" in lowered and "--no-cache" not in lowered:
            findings.append(
                make_finding(
                    "DS-DF-005",
                    "Le cache APK n'est pas nettoye (« apk add --no-cache » recommande).",
                    target,
                    evidence,
                )
            )
        if PIPE_TO_SHELL.search(command):
            findings.append(
                make_finding(
                    "DS-DF-006",
                    "Script distant execute directement dans un shell (curl | sh) : aucune verification d'integrite.",
                    target,
                    evidence,
                )
            )
        if WORLD_WRITABLE.search(command):
            findings.append(
                make_finding(
                    "DS-DF-009",
                    "Permissions 777 appliquees dans l'image (tout le monde peut modifier).",
                    target,
                    evidence,
                )
            )
        if re.search(r"(?i)git\s+clone", command) and not re.search(r"(?i)rm\s+-rf?[^\n]*\.git", command):
            findings.append(
                make_finding(
                    "DS-DF-010",
                    "« git clone » sans suppression du dossier « .git » : historique et secrets eventuels conserves.",
                    target,
                    evidence,
                )
            )
        if SUDO_USAGE.search(command):
            findings.append(
                make_finding(
                    "DS-DF-011",
                    "Utilisation de « sudo » dans l'image alors que Docker execute deja en root par defaut.",
                    target,
                    evidence,
                )
            )
        findings.extend(_check_unpinned_dependencies(instruction, target))
    return findings


def _check_unpinned_dependencies(instruction: Instruction, target: str) -> List[Finding]:
    """DS-DF-012 : dependances installees sans version figee."""
    findings: List[Finding] = []
    command = instruction.arguments
    if PINNED_PIP.search(command) and "requirements" not in command.lower():
        for package in re.findall(r"pip3?\s+install\s+([^\s;&|]+)", command):
            if package.startswith("-") or package.startswith("."):
                continue
            if "==" not in package and "@" not in package:
                findings.append(
                    make_finding(
                        "DS-DF-012",
                        f"Dependance Python non epinglee : « {package} ».",
                        target,
                        f"L{instruction.line}: {package}",
                    )
                )
    if PINNED_NPM.search(command):
        for package in re.findall(r"npm\s+(?:install|i)\s+([^\s;&|]+)", command):
            if package in ("install", "i", "-g") or package.startswith("."):
                continue
            if "@" not in package[1:]:
                findings.append(
                    make_finding(
                        "DS-DF-012",
                        f"Dependance Node non epinglee : « {package} ».",
                        target,
                        f"L{instruction.line}: {package}",
                    )
                )
    return findings


def _check_secrets(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-007 : secrets ecrits en clair dans ENV / ARG."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword not in ("ENV", "ARG"):
            continue
        pairs = _parse_key_values(instruction.arguments)
        for name, value in pairs:
            reason = secrets.judge_value(name, value)
            if not reason:
                continue
            findings.append(
                make_finding(
                    "DS-DF-007",
                    f"Secret potentiel dans {instruction.keyword} {name} ({reason}).",
                    target,
                    f"L{instruction.line}: {instruction.keyword} {name}={secrets.redact(value)}",
                )
            )
    return findings


def _parse_key_values(arguments: str) -> List[Tuple[str, str]]:
    """Analyse un argument ENV/ARG en paires cle/valeur.

    Gere les deux syntaxes : `ENV CLE=valeur AUTRE=valeur` et `ENV CLE valeur`.
    """
    pairs: List[Tuple[str, str]] = []
    tokens = arguments.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if "=" in token:
            name, _, value = token.partition("=")
            pairs.append((name.strip(), value.strip()))
            index += 1
            continue
        if index + 1 < len(tokens) and "=" not in tokens[index + 1]:
            pairs.append((token.strip(), tokens[index + 1].strip()))
            index += 2
            continue
        pairs.append((token.strip(), ""))
        index += 1
    return [(name, value) for name, value in pairs if name]


def _check_copy_add(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-008 : usage de ADD au lieu de COPY."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword != "ADD":
            continue
        arguments = instruction.arguments
        if re.search(r"(?i)https?://", arguments) or re.search(
            r"(?i)\.(tar|tar\.gz|tgz|zip|gz|bz2|xz)(\s|$)", arguments
        ):
            findings.append(
                make_finding(
                    "DS-DF-008",
                    "ADD est utilise pour recuperer une archive ou une URL distante (COPY + verification explicite recommandes).",
                    target,
                    f"L{instruction.line}: ADD {arguments[:160]}",
                )
            )
    return findings


def _check_labels(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-013 : absence de metadonnees (maintainer / labels OCI)."""
    labels: List[str] = []
    for instruction in instructions:
        if instruction.keyword == "LABEL":
            labels.extend(name for name, _value in _parse_key_values(instruction.arguments))
        elif instruction.keyword == "MAINTAINER":
            labels.append("maintainer")
    joined = " ".join(labels).lower()
    if "maintainer" in joined or "org.opencontainers.image" in joined:
        return []
    return [
        make_finding(
            "DS-DF-013",
            "Aucun label de tracabilite (maintainer ou org.opencontainers.image.*) : difficile d'auditer l'origine de l'image.",
            target,
        )
    ]


def _check_exposed_ports(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-014 : exposition de ports sensibles."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword != "EXPOSE":
            continue
        for raw_port in instruction.arguments.replace("/tcp", "").replace("/udp", "").split():
            if not raw_port.isdigit():
                continue
            port = int(raw_port)
            service = SENSITIVE_PORTS.get(port)
            if service:
                findings.append(
                    make_finding(
                        "DS-DF-014",
                        f"Port sensible expose : {port} ({service}).",
                        target,
                        f"L{instruction.line}: EXPOSE {instruction.arguments}",
                    )
                )
    return findings


def _check_misc_instructions(instructions: Sequence[Instruction], target: str) -> List[Finding]:
    """DS-DF-016 (ONBUILD) et DS-DF-017 (MAINTAINER deprecie)."""
    findings: List[Finding] = []
    for instruction in instructions:
        if instruction.keyword == "ONBUILD":
            findings.append(
                make_finding(
                    "DS-DF-016",
                    "ONBUILD execute une instruction cachee lors du build d'une image derivee.",
                    target,
                    f"L{instruction.line}: ONBUILD {instruction.arguments[:120]}",
                )
            )
        elif instruction.keyword == "MAINTAINER":
            findings.append(
                make_finding(
                    "DS-DF-017",
                    "MAINTAINER est deprecie depuis Docker 1.13 : utiliser LABEL maintainer=...",
                    target,
                    f"L{instruction.line}: MAINTAINER {instruction.arguments[:120]}",
                )
            )
    return findings


def _check_dockerignore(context_dir: Optional[str], target: str) -> List[Finding]:
    """DS-DF-018 (absence de .dockerignore) et DS-DF-019 (exclusions manquantes)."""
    if not context_dir:
        return []
    path = os.path.join(context_dir, ".dockerignore")
    if not os.path.isfile(path):
        return [
            make_finding(
                "DS-DF-018",
                "Aucun fichier .dockerignore dans le contexte de build : tout le dossier est envoye au demon.",
                target,
                os.path.join(context_dir, ".dockerignore"),
            )
        ]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read().lower()
    except OSError:
        return []
    missing = [f"{pattern} ({label})" for pattern, label in DOCKERIGNORE_REQUIRED_ENTRIES if pattern not in content]
    if not missing:
        return []
    return [
        make_finding(
            "DS-DF-019",
            "Le .dockerignore n'exclut pas des elements sensibles ou inutiles : " + ", ".join(missing) + ".",
            target,
            path,
        )
    ]


def scan_dockerfile_text(
    text: str,
    target: str = "Dockerfile",
    context_dir: Optional[str] = None,
) -> List[Finding]:
    """Analyse le contenu d'un Dockerfile et retourne les constats.

    Args:
        text: contenu du Dockerfile.
        target: nom affiche de la cible.
        context_dir: dossier de build (pour verifier .dockerignore).
    """
    instructions = parse_dockerfile(text)
    if not instructions:
        return []
    findings: List[Finding] = []
    findings.extend(_check_base_images(instructions, target))
    findings.extend(_check_user(instructions, target))
    findings.extend(_check_healthcheck(instructions, target))
    findings.extend(_check_run_commands(instructions, target))
    findings.extend(_check_secrets(instructions, target))
    findings.extend(_check_copy_add(instructions, target))
    findings.extend(_check_labels(instructions, target))
    findings.extend(_check_exposed_ports(instructions, target))
    findings.extend(_check_misc_instructions(instructions, target))
    findings.extend(_check_dockerignore(context_dir, target))
    return findings


def dockerfile_metadata(text: str) -> Dict[str, object]:
    """Quelques statistiques utiles sur le Dockerfile analyse."""
    instructions = parse_dockerfile(text)
    stages = [i for i in instructions if i.keyword == "FROM"]
    return {
        "instructions": len(instructions),
        "stages": len(stages),
        "base_images": [_base_image_reference(i) for i in stages],
        "multi_stage": len(stages) > 1,
        "instructions_by_type": _count_by_keyword(instructions),
    }


def _count_by_keyword(instructions: Sequence[Instruction]) -> Dict[str, int]:
    """Comptage des instructions par type."""
    counts: Dict[str, int] = {}
    for instruction in instructions:
        counts[instruction.keyword] = counts.get(instruction.keyword, 0) + 1
    return dict(sorted(counts.items()))


def scan_dockerfile(path: str, context_dir: Optional[str] = None) -> Tuple[List[Finding], Dict[str, object]]:
    """Analyse un Dockerfile sur disque : (constats, metadonnees)."""
    text = read_dockerfile(path)
    target = os.path.basename(path) or path
    return scan_dockerfile_text(text, target=target, context_dir=context_dir), dockerfile_metadata(text)

