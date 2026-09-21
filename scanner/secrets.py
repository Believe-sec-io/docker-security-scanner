"""Detection de secrets : motifs connus, entropie de Shannon, fichiers sensibles.

Volontairement sans dependance externe. Les valeurs detectees sont toujours
masquees avant affichage (`redact`) pour ne pas recopier un secret dans un rapport.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Dict, Iterable, List, Optional, Tuple

# --- Motifs de secrets connus -------------------------------------------------
# (nom lisible, expression reguliere, gravite)
KNOWN_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "CRITICAL"),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "CRITICAL"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "CRITICAL"),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"), "CRITICAL"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "CRITICAL"),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "CRITICAL"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"), "CRITICAL"),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "HIGH"),
    ("Generic connection string", re.compile(r"(?i)\b(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]*:[^\s'\"]*@"), "HIGH"),
    ("NPM token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "CRITICAL"),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b"), "CRITICAL"),
    ("Docker registry auth", re.compile(r"(?i)\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{16,}\""), "HIGH"),
    ("Basic auth in URL", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"), "HIGH"),
]

# --- Noms de variables ressemblant a un secret --------------------------------
SECRET_NAME_HINT = re.compile(
    r"(?i)(pass(word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|"
    r"private[-_]?key|client[-_]?secret|credential|auth|bearer|session[-_]?key|"
    r"encryption[-_]?key|signing[-_]?key|aws_|azure_|smtp|db_pass|database_password|"
    r"redis_password|jwt|ssh_key)"
)

# --- Valeurs generiques (placeholders) a ignorer ------------------------------
PLACEHOLDER_VALUES = re.compile(
    r"^(|null|none|nil|undefined|true|false|changeme|change_me|replace_me|placeholder|"
    r"example|sample|dummy|fake|todo|xxx+|test|testing|redacted|hidden|masked|\*+|\.+|"
    r"your[_\-]?[a-z_]*|my[_\-]?[a-z_]*|<[^>]*>|\[[^\]]*\]|\$\{[^}]*\}|\$[A-Z_]+)$",
    re.IGNORECASE,
)

ENV_REFERENCE = re.compile(r"(?i)^(env:|file:|\$\{|@\{|vault:|secret:|op://)")

# --- Chemins de fichiers sensibles dans une image ------------------------------
CREDENTIAL_PATH_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("SSH private key", re.compile(r"(^|/)\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519)$")),
    ("SSH authorized_keys", re.compile(r"(^|/)\.ssh/authorized_keys$")),
    ("AWS credentials", re.compile(r"(^|/)\.aws/credentials$")),
    ("Docker config auth", re.compile(r"(^|/)\.docker/config\.json$")),
    ("Git config (remote URL)", re.compile(r"(^|/)\.git/config$")),
    ("Netrc credentials", re.compile(r"(^|/)\.netrc$")),
    ("NPM credentials", re.compile(r"(^|/)\.npmrc$")),
    ("PyPI credentials", re.compile(r"(^|/)\.pypirc$")),
    ("Env file", re.compile(r"(^|/)(\.env|\.env\.[a-z0-9_]+)$")),
    ("Kubernetes config", re.compile(r"(^|/)\.kube/config$")),
    ("Password file", re.compile(r"(^|/)(htpasswd|\.htpasswd|shadow\.bak)$")),
    ("Private certificate/key", re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.IGNORECASE)),
    ("Terraform state", re.compile(r"\.tfstate$", re.IGNORECASE)),
    ("Database dump", re.compile(r"\.(sql|sqlite|sqlite3|db)$", re.IGNORECASE)),
]


def shannon_entropy(value: str) -> float:
    """Entropie de Shannon (bits par caractere) - utile pour reperer un secret."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    """Vrai si la valeur est vide, un placeholder ou une reference d'environnement."""
    text = (value or "").strip().strip("'\"")
    if not text:
        return True
    if ENV_REFERENCE.match(text):
        return True
    return bool(PLACEHOLDER_VALUES.match(text))


def is_high_entropy(value: str, threshold: float = 3.4, min_length: int = 20) -> bool:
    """Heuristique : chaine longue, sans espace, a forte entropie (candidat secret)."""
    text = (value or "").strip().strip("'\"")
    if len(text) < min_length or " " in text:
        return False
    if text.startswith(("/", "\\", "./", "../", "http://", "https://", "git@")):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-]*(/[A-Za-z0-9_\-\.]+)*", text):
        return False  # chemin de fichier, namespace ou nom d'image
    return shannon_entropy(text) >= threshold


def looks_like_secret_name(name: str) -> bool:
    """Vrai si le nom de la variable suggere un secret."""
    return bool(SECRET_NAME_HINT.search(name or ""))


def judge_value(name: str, value: str) -> Optional[str]:
    """Evalue une paire nom/valeur et retourne la raison si c'est un secret."""
    if is_placeholder(value):
        return None
    for label, pattern, _severity in KNOWN_PATTERNS:
        if pattern.search(value or ""):
            return f"motif reconnu : {label}"
    if looks_like_secret_name(name) and len((value or "").strip()) >= 8:
        return f"variable sensible « {name} » avec une valeur en clair"
    if is_high_entropy(value):
        return f"valeur a forte entropie ({shannon_entropy(value):.1f} bits/car.)"
    return None


def scan_text_for_secrets(text: str) -> List[Tuple[str, str]]:
    """Cherche des secrets dans un texte libre (historique de build, script...).

    Retourne une liste de tuples (label du motif, valeur masquee).
    """
    if not text:
        return []
    results: List[Tuple[str, str]] = []
    for label, pattern, _severity in KNOWN_PATTERNS:
        for match in pattern.finditer(text):
            results.append((label, redact(match.group(0))))
    return results


def scan_mapping_for_secrets(mapping: Dict[str, str]) -> List[Tuple[str, str]]:
    """Analyse un dictionnaire cle/valeur (variables d'environnement, labels...)."""
    results: List[Tuple[str, str]] = []
    for name, value in (mapping or {}).items():
        reason = judge_value(str(name), str(value))
        if reason:
            results.append((f"{name} ({reason})", redact(str(value))))
    return results


def credential_path_label(path: str) -> Optional[str]:
    """Retourne le type de fichier sensible si le chemin correspond, sinon None."""
    normalized = "/" + str(path).replace("\\", "/").lstrip("./")
    for label, pattern in CREDENTIAL_PATH_PATTERNS:
        if pattern.search(normalized):
            return label
    return None


def redact(value: str, keep: int = 4) -> str:
    """Masque une valeur sensible : garde un court prefixe lisible."""
    text = str(value or "")
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * 8}{text[-keep:]}"


def is_private_ip(value: str) -> bool:
    """Vrai si la chaine est une adresse IP privee (utile pour les binds exposes)."""
    try:
        return ipaddress.ip_address(str(value).strip()).is_private
    except ValueError:
        return False


def iter_secret_evidence(values: Iterable[str]) -> List[str]:
    """Filtre une collection de valeurs et garde celles qui ressemblent a un secret."""
    return [redact(v) for v in values if judge_value("", str(v))]
