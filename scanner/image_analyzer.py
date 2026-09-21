"""Analyse hors-ligne d'une image Docker exportee avec `docker save`.

Fonctionne sans demon Docker : l'archive (format classique `manifest.json` ou
layout OCI `index.json`) est lue avec `tarfile`, la configuration JSON et
l'historique de build sont analyses, puis chaque couche est inspectee
(fichiers sensibles, permissions dangereuses, comptes sans mot de passe...).
"""

from __future__ import annotations

import json
import os
import re
import tarfile
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

from . import secrets
from .dockerfile_rules import EOL_PATTERNS, SENSITIVE_PORTS
from .models import Finding
from .rules import make_finding

# Taille maximale lue dans un fichier de couche (protection memoire)
MAX_MEMBER_READ = 2 * 1024 * 1024

SHELL_FORM = re.compile(r"^\s*(/bin/)?(ba|z|k|da)?sh\s+-c\b")

SENSITIVE_VOLUME_PATHS = (
    "/var/run/docker.sock",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/var/lib/docker",
    "/home",
)

OCI_LABEL_PREFIX = "org.opencontainers.image"


@dataclass
class ImageScanOptions:
    """Options d'analyse d'image (limites de protection)."""

    max_size_mb: float = 1500.0
    max_layers: int = 20
    max_members_per_layer: int = 20000
    scan_layer_content: bool = True

    @classmethod
    def from_args(cls, args) -> "ImageScanOptions":
        """Construit les options depuis les arguments de la ligne de commande."""
        return cls(
            max_size_mb=float(getattr(args, "max_size_mb", 1500.0)),
            max_layers=int(getattr(args, "max_layers", 20)),
            max_members_per_layer=int(getattr(args, "max_members_per_layer", 20000)),
            scan_layer_content=not bool(getattr(args, "skip_layer_content", False)),
        )


@dataclass
class LayerInfo:
    """Information sur une couche de l'image."""

    name: str
    size: int


class ImageArchive:
    """Acces lecture seule a une archive d'image Docker / OCI."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.size = os.path.getsize(path)
        self.tar = tarfile.open(path, "r:*")
        self.names: Set[str] = set(self.tar.getnames())
        self.format: str
        self.repo_tags: List[str]
        self.config_name: str
        self.layer_names: List[str]
        self.format, self.repo_tags, self.config_name, self.layer_names = self._read_layout()
        self._config: Optional[Dict[str, object]] = None

    # ----------------------------------------------------------- chargement
    def _text(self, name: str) -> str:
        """Lit un membre textuel de l'archive."""
        handle = self.tar.extractfile(self.tar.getmember(name))
        if handle is None:
            raise ValueError(f"Membre illisible : {name}")
        with handle:
            return handle.read().decode("utf-8", "replace")

    def _json(self, name: str) -> object:
        """Lit un membre JSON de l'archive."""
        return json.loads(self._text(name))

    def _blob_name(self, digest: str) -> str:
        """Convertit un digest OCI en nom de membre (blobs/sha256/xxx)."""
        if digest.startswith("sha256:"):
            candidate = "blobs/sha256/" + digest.split(":", 1)[1]
            if candidate in self.names:
                return candidate
        return digest

    def _read_layout(self) -> Tuple[str, List[str], str, List[str]]:
        """Detecte le format de l'archive et retourne tags / config / couches."""
        if "manifest.json" in self.names:
            manifest = self._json("manifest.json")
            entry = manifest[0] if isinstance(manifest, list) and manifest else {}
            if not isinstance(entry, dict):
                raise ValueError("manifest.json invalide")
            return (
                "docker",
                [str(tag) for tag in (entry.get("RepoTags") or [])],
                str(entry.get("Config") or ""),
                [str(name) for name in (entry.get("Layers") or [])],
            )
        if "index.json" in self.names:
            index = self._json("index.json")
            manifests = index.get("manifests", []) if isinstance(index, dict) else []
            if not manifests:
                raise ValueError("index.json sans manifeste")
            reference = manifests[0]
            manifest = self._json(self._blob_name(str(reference.get("digest", ""))))
            annotations = reference.get("annotations") or {}
            ref_name = annotations.get("org.opencontainers.image.ref.name")
            tags = [str(ref_name)] if ref_name else []
            layers = [self._blob_name(str(layer.get("digest", ""))) for layer in manifest.get("layers", [])]
            config = self._blob_name(str((manifest.get("config") or {}).get("digest", "")))
            return "oci", tags, config, layers
        raise ValueError("Archive non reconnue : ni manifest.json ni index.json trouve")

    # ------------------------------------------------------------- accesseurs
    def config(self) -> Dict[str, object]:
        """Configuration complete de l'image (mise en cache)."""
        if self._config is None:
            self._config = self._json(self.config_name) if self.config_name else {}
        return self._config or {}

    def image_config(self) -> Dict[str, object]:
        """Section `config` : User, Env, ExposedPorts, Cmd, Labels, Volumes..."""
        value = self.config().get("config") or {}
        return value if isinstance(value, dict) else {}

    def history(self) -> List[Dict[str, object]]:
        """Historique de build (champ `created_by`)."""
        value = self.config().get("history") or []
        return [entry for entry in value if isinstance(entry, dict)]

    def labels(self) -> Dict[str, str]:
        """Labels de l'image."""
        value = self.image_config().get("Labels") or {}
        return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}

    def env(self) -> Dict[str, str]:
        """Variables d'environnement declarees dans l'image."""
        result: Dict[str, str] = {}
        for item in self.image_config().get("Env") or []:
            name, _, value = str(item).partition("=")
            result[name] = value
        return result

    def exposed_ports(self) -> List[int]:
        """Ports declares dans la configuration de l'image."""
        ports: List[int] = []
        raw = self.image_config().get("ExposedPorts") or {}
        for key in raw if isinstance(raw, dict) else []:
            port = str(key).split("/")[0]
            if port.isdigit():
                ports.append(int(port))
        return sorted(ports)

    def layers(self) -> List[LayerInfo]:
        """Liste des couches (nom, taille compressee)."""
        result: List[LayerInfo] = []
        for name in self.layer_names:
            try:
                result.append(LayerInfo(name, int(self.tar.getmember(name).size)))
            except KeyError:
                result.append(LayerInfo(name, 0))
        return result

    def iter_members(self, layer_name: str) -> Iterator[tarfile.TarInfo]:
        """Itere sur les membres d'une couche sans rien extraire sur le disque."""
        try:
            outer = self.tar.extractfile(self.tar.getmember(layer_name))
        except KeyError:
            return
        if outer is None:
            return
        with outer:
            try:
                with tarfile.open(fileobj=outer, mode="r|*") as layer:
                    for entry in layer:
                        yield entry
            except (tarfile.TarError, OSError):
                return

    def read_member(self, layer_name: str, target: str, limit: int = MAX_MEMBER_READ) -> Optional[bytes]:
        """Lit un fichier precis d'une couche (taille plafonnee par `limit`)."""
        try:
            outer = self.tar.extractfile(self.tar.getmember(layer_name))
        except KeyError:
            return None
        if outer is None:
            return None
        wanted = str(target).lstrip("./")
        with outer:
            try:
                with tarfile.open(fileobj=outer, mode="r|*") as layer:
                    for entry in layer:
                        if entry.isfile() and entry.name.lstrip("./") == wanted:
                            handle = layer.extractfile(entry)
                            if handle is None:
                                return None
                            with handle:
                                return handle.read(limit)
            except (tarfile.TarError, OSError):
                return None
        return None

    def close(self) -> None:
        """Ferme l'archive."""
        self.tar.close()

    def __enter__(self) -> "ImageArchive":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()



# --------------------------------------------------------------------------- #
#                              Regles image                                   #
# --------------------------------------------------------------------------- #

def _check_config_user(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-001 : image configuree pour tourner en root."""
    user = str(archive.image_config().get("User", "") or "").strip()
    if user and user.split(":")[0].lower() not in ("root", "0"):
        return []
    return [
        make_finding(
            "DS-IMG-001",
            "L'image n'impose aucun utilisateur non-root (config.User vide ou egal a root).",
            target,
            f"config.User = {user or '<vide>'}",
        )
    ]


def _check_config_healthcheck(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-002 : absence de HEALTHCHECK."""
    if archive.image_config().get("Healthcheck"):
        return []
    return [
        make_finding(
            "DS-IMG-002",
            "Aucun HEALTHCHECK dans l'image : l'orchestrateur ne peut pas detecter un service bloque.",
            target,
        )
    ]


def _check_config_env_secrets(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-003 : secret present dans les variables d'environnement."""
    findings: List[Finding] = []
    for label, masked in secrets.scan_mapping_for_secrets(archive.env()):
        findings.append(
            make_finding(
                "DS-IMG-003",
                f"Variable d'environnement contenant un secret probable : {label}.",
                target,
                masked,
            )
        )
    return findings


def _check_config_ports(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-011 : port sensible expose par la configuration."""
    findings: List[Finding] = []
    for port in archive.exposed_ports():
        service = SENSITIVE_PORTS.get(port)
        if service:
            findings.append(
                make_finding(
                    "DS-IMG-011",
                    f"Port sensible expose par l'image : {port} ({service}).",
                    target,
                    f"ExposedPorts {port}/tcp",
                )
            )
    return findings


def _check_config_labels(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-010 : labels OCI absents."""
    labels = archive.labels()
    joined = " ".join(labels.keys()).lower() + " " + " ".join(labels.values()).lower()
    if "maintainer" in labels or OCI_LABEL_PREFIX in joined:
        return []
    return [
        make_finding(
            "DS-IMG-010",
            "Aucun label OCI (org.opencontainers.image.*) ni « maintainer » : tracabilite insuffisante.",
            target,
        )
    ]


def _check_config_volumes(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-016 : volume declare sur un chemin sensible."""
    findings: List[Finding] = []
    volumes = archive.image_config().get("Volumes") or {}
    for path in volumes if isinstance(volumes, dict) else []:
        normalized = str(path).rstrip("/") or "/"
        if any(normalized == sensitive or normalized.startswith(sensitive + "/") for sensitive in SENSITIVE_VOLUME_PATHS):
            findings.append(
                make_finding(
                    "DS-IMG-016",
                    f"Volume declare sur un chemin sensible : {path} (peut exposer l'hote).",
                    target,
                    f"Volumes {path}",
                )
            )
    return findings

def _check_config_cmd_form(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-012 : CMD/ENTRYPOINT en forme shell."""
    config = archive.image_config()
    findings: List[Finding] = []
    for key in ("Cmd", "Entrypoint"):
        value = config.get(key)
        if isinstance(value, str) and SHELL_FORM.match(value):
            findings.append(
                make_finding(
                    "DS-IMG-012",
                    f"{key} utilise la forme shell : les signaux (SIGTERM) ne sont pas transmis au processus.",
                    target,
                    f"{key} = {value[:120]}",
                )
            )
    return findings


def _check_config_workdir(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-017 : repertoire de travail non defini."""
    workdir = str(archive.image_config().get("WorkingDir", "") or "").strip()
    if workdir and workdir != "/":
        return []
    return [
        make_finding(
            "DS-IMG-017",
            "Aucun WorkingDir explicite dans l'image.",
            target,
            f"config.WorkingDir = {workdir or '<vide>'}",
        )
    ]


def _check_image_reference(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-008 : reference d'image mutable (latest ou sans tag)."""
    findings: List[Finding] = []
    for tag in archive.repo_tags or ["<aucun tag>"]:
        image = tag.split("/")[-1]
        if tag == "<aucun tag>" or image.endswith(":latest") or ":" not in image:
            findings.append(
                make_finding(
                    "DS-IMG-008",
                    f"Reference d'image mutable : « {tag} » (deploiement non reproductible).",
                    target,
                    tag,
                )
            )
    return findings


def _check_layer_count(archive: ImageArchive, options: ImageScanOptions, target: str) -> List[Finding]:
    """DS-IMG-009 : nombre de couches excessif."""
    count = len(archive.layer_names)
    if count <= options.max_layers:
        return []
    return [
        make_finding(
            "DS-IMG-009",
            f"{count} couches detectees (seuil {options.max_layers}) : secrets residuels probables, image difficile a maintenir.",
            target,
            f"layers = {count}",
        )
    ]


def _check_image_size(archive: ImageArchive, options: ImageScanOptions, target: str) -> List[Finding]:
    """DS-IMG-013 : image trop volumineuse."""
    total = sum(layer.size for layer in archive.layers())
    limit = options.max_size_mb * 1024 * 1024
    if total <= limit:
        return []
    return [
        make_finding(
            "DS-IMG-013",
            f"Taille de l'image {total / 1048576:.0f} Mo superieure au seuil de {options.max_size_mb:.0f} Mo.",
            target,
            f"taille = {total} octets",
        )
    ]


def _check_docker_version(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-015 : image construite avec un Docker ancien."""
    version = str(archive.config().get("docker_version", "") or "")
    match = re.match(r"^(\d+)\.(\d+)", version)
    if not match:
        return []
    major, minor = int(match.group(1)), int(match.group(2))
    if (major, minor) >= (19, 3):
        return []
    return [
        make_finding(
            "DS-IMG-015",
            f"Image construite avec Docker {version} (support/outillage anciens).",
            target,
            f"docker_version = {version}",
        )
    ]



def _check_layer_contents(archive: ImageArchive, options: ImageScanOptions, target: str) -> List[Finding]:
    """DS-IMG-004/005/006/014 : inspection des fichiers de chaque couche."""
    findings: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()
    if not options.scan_layer_content:
        return findings

    for layer in archive.layers():
        credentials: List[str] = []
        setuid: List[str] = []
        writable: List[str] = []
        shadow_data: Optional[bytes] = None
        count = 0

        for entry in archive.iter_members(layer.name):
            count += 1
            if count > options.max_members_per_layer:
                break
            path = str(entry.name)
            label = secrets.credential_path_label(path)
            if label and not entry.isdir():
                credentials.append(f"{path} ({label})")
            if entry.isfile() and (entry.mode & 0o4000 or entry.mode & 0o2000):
                setuid.append(f"{path} (mode {entry.mode:o})")
            if (entry.mode & 0o002) and not entry.issym():
                writable.append(f"{path} (mode {entry.mode:o})")
            if path.endswith("/etc/shadow") and entry.isfile():
                shadow_data = b"shadow"

        if credentials:
            key = ("DS-IMG-004", layer.name)
            if key not in seen:
                seen.add(key)
                findings.append(
                    make_finding(
                        "DS-IMG-004",
                        f"Fichiers de credentials presents dans la couche ({len(credentials)} fichier(s)).",
                        target,
                        "; ".join(sorted(credentials)[:6]),
                    )
                )
        if setuid:
            findings.append(
                make_finding(
                    "DS-IMG-005",
                    f"Binaires setuid/setgid detectes ({len(setuid)}) : vecteur d'escalade de privileges.",
                    target,
                    "; ".join(sorted(setuid)[:6]),
                )
            )
        if writable:
            findings.append(
                make_finding(
                    "DS-IMG-006",
                    f"Fichiers modifiables par tous (mode o+w) detectes ({len(writable)}).",
                    target,
                    "; ".join(sorted(writable)[:6]),
                )
            )
        if shadow_data is not None:
            content = archive.read_member(layer.name, "etc/shadow") or b""
            findings.extend(_check_shadow_file(content, target, layer.name))
    return findings


def _check_shadow_file(content: bytes, target: str, layer_name: str) -> List[Finding]:
    """DS-IMG-014 : comptes sans mot de passe dans /etc/shadow."""
    if not content:
        return []
    empty_accounts: List[str] = []
    for line in content.decode("utf-8", "replace").splitlines():
        fields = line.split(":")
        if len(fields) >= 2 and fields[0] and fields[1] == "":
            empty_accounts.append(fields[0])
    if not empty_accounts:
        return []
    return [
        make_finding(
            "DS-IMG-014",
            f"Comptes sans mot de passe dans /etc/shadow : {', '.join(empty_accounts)}.",
            target,
            f"{layer_name}:etc/shadow",
        )
    ]


def _check_history(archive: ImageArchive, target: str) -> List[Finding]:
    """DS-IMG-007 (secrets dans l'historique) et DS-IMG-018 (base en fin de vie)."""
    findings: List[Finding] = []
    leaked: List[str] = []
    eol: Set[str] = set()

    for entry in archive.history():
        created_by = str(entry.get("created_by", "") or "")
        for label, masked in secrets.scan_text_for_secrets(created_by):
            leaked.append(f"{label} -> {masked}")
        for pattern, reason in EOL_PATTERNS:
            if pattern.search(created_by):
                eol.add(f"{created_by[:100]} ({reason})")
                break

    if leaked:
        findings.append(
            make_finding(
                "DS-IMG-007",
                f"Secret present dans l'historique de build ({len(leaked)} occurrence(s)) : visible via « docker history ».",
                target,
                "; ".join(sorted(set(leaked))[:6]),
            )
        )
    if eol:
        findings.append(
            make_finding(
                "DS-IMG-018",
                "Historique de build : image de base en fin de support detectee.",
                target,
                "; ".join(sorted(eol)[:3]),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
#                              API publique                                   #
# --------------------------------------------------------------------------- #

def image_metadata(archive: ImageArchive) -> Dict[str, object]:
    """Metadonnees synthetiques de l'image analysee."""
    config = archive.config()
    image_config = archive.image_config()
    layers = archive.layers()
    return {
        "format": archive.format,
        "archive": os.path.basename(archive.path),
        "archive_size": archive.size,
        "image_id": str(config.get("id", "") or "")[:32],
        "repo_tags": list(archive.repo_tags),
        "created": str(config.get("created", "") or ""),
        "architecture": str(config.get("architecture", "") or ""),
        "os": str(config.get("os", "") or ""),
        "docker_version": str(config.get("docker_version", "") or ""),
        "user": str(image_config.get("User", "") or "") or "root (par defaut)",
        "entrypoint": image_config.get("Entrypoint"),
        "cmd": image_config.get("Cmd"),
        "working_dir": str(image_config.get("WorkingDir", "") or ""),
        "exposed_ports": archive.exposed_ports(),
        "environment_variables": len(archive.env()),
        "labels": list(archive.labels().keys()),
        "volumes": list((image_config.get("Volumes") or {}).keys()) if isinstance(image_config.get("Volumes"), dict) else [],
        "layers": len(layers),
        "uncompressed_size": sum(layer.size for layer in layers),
        "history_entries": len(archive.history()),
    }


def analyze_image(
    archive: ImageArchive,
    options: Optional[ImageScanOptions] = None,
    target: Optional[str] = None,
) -> Tuple[List[Finding], Dict[str, object]]:
    """Analyse une archive d'image ouverte et retourne (constats, metadonnees)."""
    options = options or ImageScanOptions()
    label = target or (archive.repo_tags[0] if archive.repo_tags else os.path.basename(archive.path))
    findings: List[Finding] = []
    findings.extend(_check_config_user(archive, label))
    findings.extend(_check_config_healthcheck(archive, label))
    findings.extend(_check_config_env_secrets(archive, label))
    findings.extend(_check_config_ports(archive, label))
    findings.extend(_check_config_labels(archive, label))
    findings.extend(_check_config_volumes(archive, label))
    findings.extend(_check_config_cmd_form(archive, label))
    findings.extend(_check_config_workdir(archive, label))
    findings.extend(_check_image_reference(archive, label))
    findings.extend(_check_layer_count(archive, options, label))
    findings.extend(_check_image_size(archive, options, label))
    findings.extend(_check_docker_version(archive, label))
    findings.extend(_check_history(archive, label))
    findings.extend(_check_layer_contents(archive, options, label))
    return findings, image_metadata(archive)


def scan_image_tar(
    path: str,
    options: Optional[ImageScanOptions] = None,
    target: Optional[str] = None,
) -> Tuple[List[Finding], Dict[str, object]]:
    """Analyse une image exportee (`docker save`) depuis un fichier tar/tar.gz."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Archive introuvable : {path}")
    with ImageArchive(path) as archive:
        return analyze_image(archive, options, target)


def format_size(size: float) -> str:
    """Formate une taille en octets de facon lisible."""
    units = ("o", "Ko", "Mo", "Go", "To")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == units[0] else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} To"

