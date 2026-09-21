#!/usr/bin/env python3
"""Docker Security Scanner - point d'entree en ligne de commande.

Exemples :
    python docker_scanner.py --dockerfile examples/Dockerfile.insecure
    python docker_scanner.py --image-tar nginx.tar --format html -o rapport.html
    python docker_scanner.py --image mon-app:1.2.3 --fail-on high
    python docker_scanner.py --container mon-conteneur
    python docker_scanner.py .            # analyse tous les Dockerfile d'un dossier
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional, Sequence, Tuple

from scanner import __version__, dockerfile_rules, image_analyzer, reporters, runtime_checks
from scanner.models import Report
from scanner.rules import load_rules

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info", "never")
SEVERITY_CHOICES = ("critical", "high", "medium", "low", "info")
DOCKERFILE_NAMES = ("dockerfile", "containerfile")
IMAGE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".oci", ".zip")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments de l'outil."""
    parser = argparse.ArgumentParser(
        prog="docker_security_scanner",
        description="Audit de securite hors-ligne des Dockerfiles, images et conteneurs.",
        epilog="Astuce : --list-rules affiche le catalogue complet des regles (50 controles).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Cible : Dockerfile, dossier, archive d'image ou nom d'image")
    parser.add_argument("--dockerfile", metavar="CHEMIN", help="Analyser un Dockerfile")
    parser.add_argument("--image-tar", dest="image_tar", metavar="ARCHIVE", help="Analyser une image exportee (docker save)")
    parser.add_argument("--image", metavar="NOM", help="Analyser une image locale (necessite Docker)")
    parser.add_argument("--container", metavar="NOM", help="Analyser un conteneur en execution (necessite Docker)")
    parser.add_argument("--context", metavar="DOSSIER", help="Contexte de build (pour la verification .dockerignore)")
    parser.add_argument("-f", "--format", default="console", choices=["console", "json", "html", "markdown"], help="Format du rapport")
    parser.add_argument("-o", "--output", metavar="FICHIER", help="Ecrire le rapport dans un fichier")
    parser.add_argument("--min-severity", default="info", type=str.lower, choices=SEVERITY_CHOICES, help="Ne montrer que les constats >= cette gravite")
    parser.add_argument("--ignore", default="", help="Regles a ignorer, separees par des virgules (ex. DS-DF-003,DS-IMG-017)")
    parser.add_argument("--fail-on", default="never", type=str.lower, choices=FAIL_ON_CHOICES, help="Code de sortie 1 si un constat >= ce seuil (ideal en CI)")
    parser.add_argument("--max-size-mb", dest="max_size_mb", type=float, default=1500.0, help="Seuil de taille d'image en Mo")
    parser.add_argument("--max-layers", dest="max_layers", type=int, default=20, help="Nombre de couches considere comme excessif")
    parser.add_argument("--skip-layer-content", dest="skip_layer_content", action="store_true", help="Ne pas inspecter le contenu des couches")
    parser.add_argument("--no-color", action="store_true", help="Desactiver les couleurs ANSI")
    parser.add_argument("--quiet", action="store_true", help="Ne pas afficher le rapport sur la sortie standard")
    parser.add_argument("--list-rules", action="store_true", help="Afficher le catalogue des regles puis quitter")
    parser.add_argument("--version", action="version", version=f"Docker Security Scanner {__version__}")
    return parser


# --------------------------------------------------------------------------- #
#                          Detection de la cible                              #
# --------------------------------------------------------------------------- #

def is_dockerfile_path(path: str) -> bool:
    """Vrai si le chemin ressemble a un Dockerfile."""
    name = os.path.basename(path).lower()
    return name.startswith(DOCKERFILE_NAMES) or name.endswith((".dockerfile", ".containerfile"))


def find_dockerfiles(directory: str) -> List[str]:
    """Liste recursivement les Dockerfiles d'un dossier."""
    found: List[str] = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.lower().startswith(DOCKERFILE_NAMES) or name.lower().endswith((".dockerfile", ".containerfile")):
                found.append(os.path.join(root, name))
    return found


def detect_target(args: argparse.Namespace) -> Tuple[str, str]:
    """Determine (type de cible, valeur) a partir des options et du positionnel."""
    for kind, value in (
        ("dockerfile", args.dockerfile),
        ("image-tar", args.image_tar),
        ("image", args.image),
        ("container", args.container),
    ):
        if value:
            return kind, value
    target = args.target
    if not target:
        raise SystemExit("Erreur : aucune cible fournie (voir --help).")
    if os.path.isdir(target):
        return "directory", target
    if os.path.isfile(target):
        if is_dockerfile_path(target):
            return "dockerfile", target
        if target.lower().endswith(IMAGE_SUFFIXES):
            return "image-tar", target
        raise SystemExit(f"Erreur : fichier non reconnu comme Dockerfile ou archive d'image : {target}")
    return "image", target



# --------------------------------------------------------------------------- #
#                          Execution des analyses                             #
# --------------------------------------------------------------------------- #

def scan_dockerfile_target(path: str, args: argparse.Namespace, report: Report) -> None:
    """Analyse un Dockerfile et alimente le rapport."""
    context = args.context or os.path.dirname(os.path.abspath(path))
    findings, metadata = dockerfile_rules.scan_dockerfile(path, context_dir=context)
    report.extend(findings)
    report.metadata.update({"dockerfile": path, **metadata})


def scan_directory_target(directory: str, args: argparse.Namespace, report: Report) -> None:
    """Analyse tous les Dockerfiles d'un dossier."""
    paths = find_dockerfiles(directory)
    report.metadata["directory"] = os.path.abspath(directory)
    report.metadata["dockerfiles_found"] = len(paths)
    if not paths:
        report.metadata["note"] = "Aucun Dockerfile trouve dans ce dossier."
        return
    report.metadata["dockerfiles"] = [os.path.relpath(p, directory) for p in paths]
    for path in paths:
        findings, _meta = dockerfile_rules.scan_dockerfile(path, context_dir=os.path.dirname(os.path.abspath(path)))
        report.extend(findings)


def scan_image_tar_target(path: str, args: argparse.Namespace, report: Report) -> None:
    """Analyse une archive d'image exportee."""
    options = image_analyzer.ImageScanOptions.from_args(args)
    findings, metadata = image_analyzer.scan_image_tar(path, options=options)
    report.extend(findings)
    report.metadata.update(metadata)


def scan_image_target(name: str, args: argparse.Namespace, report: Report) -> None:
    """Analyse une image locale via `docker save` (necessite le demon Docker)."""
    if not runtime_checks.docker_available():
        report.extend(docker_missing_findings("image", name))
        return
    options = image_analyzer.ImageScanOptions.from_args(args)
    handle, temp_path = tempfile.mkstemp(prefix="dss-image-", suffix=".tar")
    os.close(handle)
    try:
        runtime_checks.save_image(name, temp_path)
        findings, metadata = image_analyzer.scan_image_tar(temp_path, options=options, target=name)
        report.extend(findings)
        report.metadata.update(metadata)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def scan_container_target(name: str, args: argparse.Namespace, report: Report) -> None:
    """Analyse un conteneur en execution (necessite le demon Docker)."""
    if not runtime_checks.docker_available():
        report.extend(docker_missing_findings("container", name))
        return
    findings, metadata = runtime_checks.scan_container(name)
    report.extend(findings)
    report.metadata.update(metadata)


def docker_missing_findings(kind: str, name: str):
    """Constats informatifs lorsque le demon Docker est indisponible."""
    from scanner.rules import make_finding

    return [
        make_finding(
            "DS-GEN-001",
            f"Analyse « {kind} » impossible pour « {name} » : le client Docker n'est pas disponible sur cette machine.",
            target=name,
            evidence="docker introuvable dans le PATH",
        )
    ]


def force_utf8_output() -> None:
    """Force UTF-8 sur la sortie standard (console Windows en cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue


def print_rules() -> None:
    """Affiche le catalogue des regles disponibles."""
    rules = load_rules()
    print(f"📚 Catalogue de regles — {len(rules)} controles disponibles")
    print("=" * 96)
    category = None
    for rule_id in sorted(rules):
        definition = rules[rule_id]
        if definition.get("category") != category:
            category = definition.get("category")
            print(f"\n[{category.upper()}]")
        print(
            f"  {rule_id:<11} {definition.get('severity', 'INFO'):<8} "
            f"{definition.get('title', '')}"
        )
    print("\nUtilisation : --ignore DS-DF-003,DS-IMG-017 pour exclure des regles.")


def write_output(content: str, path: str) -> None:
    """Ecrit le rapport dans un fichier (UTF-8)."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Point d'entree : retourne le code de sortie du programme."""
    parser = build_parser()
    args = parser.parse_args(argv)
    force_utf8_output()

    if args.list_rules:
        print_rules()
        return 0

    try:
        target_type, target_value = detect_target(args)
    except SystemExit as error:
        print(str(error), file=sys.stderr)
        return 2

    report = Report(target=target_value, target_type=target_type)
    try:
        if target_type == "dockerfile":
            scan_dockerfile_target(target_value, args, report)
        elif target_type == "directory":
            scan_directory_target(target_value, args, report)
        elif target_type == "image-tar":
            scan_image_tar_target(target_value, args, report)
        elif target_type == "image":
            scan_image_target(target_value, args, report)
        elif target_type == "container":
            scan_container_target(target_value, args, report)
        else:
            print(f"Erreur : type de cible inconnu « {target_type} ».", file=sys.stderr)
            return 2
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"❌ Echec de l'analyse : {error}", file=sys.stderr)
        return 2

    ignored = [item for item in args.ignore.split(",") if item.strip()]
    report = report.filtered(min_severity=args.min_severity.upper(), ignore_rules=ignored)
    content = reporters.render(report, fmt=args.format, use_color=not args.no_color)

    if args.output:
        try:
            write_output(content, args.output)
        except OSError as error:
            print(f"❌ Impossible d'ecrire le rapport : {error}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"📄 Rapport {args.format} ecrit dans {args.output}")
    if not args.quiet and not args.output:
        print(content)
    elif not args.quiet and args.output and args.format == "console":
        print(content)

    counts = report.counts()
    if args.fail_on != "never" and report.has_findings_at_or_above(args.fail_on.upper()):
        print(
            f"⛔ Seuil --fail-on {args.fail_on.upper()} atteint "
            f"(CRITICAL {counts['CRITICAL']}, HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']}).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

