"""Rendus de rapport : console coloree, JSON, HTML autonome et Markdown.

Aucune ressource externe n'est referencee : le rapport HTML est totalement
autonome (CSS embarque) pour pouvoir etre archive ou envoye tel quel.
"""

from __future__ import annotations

import html
import json
from typing import Dict, List

from .models import SEVERITIES, Finding, Report, risk_label, severity_value

RESET = "\033[0m"
ANSI_COLORS: Dict[str, str] = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[1;34m",
}
SEVERITY_ICONS: Dict[str, str] = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟦",
    "INFO": "⬜",
}
TITLE = "🐳 Docker Security Scanner"


def render(report: Report, fmt: str = "console", use_color: bool = True) -> str:
    """Point d'entree : rend le rapport dans le format demande."""
    normalized = (fmt or "console").lower()
    if normalized in ("console", "text", "txt"):
        return render_console(report, use_color=use_color)
    if normalized == "json":
        return render_json(report)
    if normalized in ("html", "htm"):
        return render_html(report)
    if normalized in ("md", "markdown"):
        return render_markdown(report)
    raise ValueError(f"Format de sortie inconnu : {fmt}")


def render_json(report: Report) -> str:
    """Rapport JSON (indente, stable, facile a consommer en CI)."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _colorize(text: str, severity: str, use_color: bool) -> str:
    """Applique la couleur ANSI de la gravite si demande."""
    if not use_color:
        return text
    return f"{ANSI_COLORS.get(severity, '')}{text}{RESET}"


def render_console(report: Report, use_color: bool = True) -> str:
    """Rapport lisible en terminal."""
    counts = report.counts()
    score = report.risk_score()
    lines: List[str] = []
    rule = "=" * 74
    lines.append(rule)
    lines.append(f" {TITLE} — rapport de securite")
    lines.append(rule)
    lines.append(f" 🎯 Cible          : {report.target}")
    lines.append(f" 🧩 Type de cible   : {report.target_type}")
    lines.append(f" ⚖️  Score de risque : {score}/100 (note {report.grade()} — {risk_label(score)})")
    summary = " | ".join(f"{sev} {counts[sev]}" for sev in SEVERITIES)
    lines.append(f" 🔎 Constats        : {len(report.findings)}  ({summary})")

    if report.metadata:
        lines.append("-" * 74)
        lines.append(" 📦 Details de la cible")
        for key, value in report.metadata.items():
            if value in ("", None, [], {}):
                continue
            lines.append(f"    {key:<22}: {value}")

    lines.append("-" * 74)
    if not report.findings:
        lines.append(" ✅ Aucun constat pour cette cible.")
    for finding in report.findings:
        icon = SEVERITY_ICONS.get(finding.severity, "•")
        header = f" {icon} {finding.severity:<8} {finding.rule_id:<11} {finding.title}"
        lines.append(_colorize(header, finding.severity, use_color))
        lines.append(f"    detail    : {finding.message}")
        if finding.evidence:
            lines.append(f"    preuve    : {finding.evidence}")
        if finding.remediation:
            lines.append(f"    correctif : {finding.remediation}")
    lines.append(rule)
    lines.append(" 💡 Astuce : --format json|html|markdown pour un rapport exploitable, --fail-on high pour la CI.")
    return "\n".join(lines)



def render_markdown(report: Report) -> str:
    """Rapport Markdown (pratique pour un commentaire de PR)."""
    counts = report.counts()
    score = report.risk_score()
    lines: List[str] = [
        f"# {TITLE} — rapport",
        "",
        f"- **Cible** : `{report.target}` ({report.target_type})",
        f"- **Score de risque** : {score}/100 (note **{report.grade()}**, {risk_label(score)})",
        f"- **Date** : {report.generated_at}",
        "",
        "## Resume",
        "",
        "| Gravite | Nombre |",
        "|---------|--------|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {counts[severity]} |")
    lines.append(f"| **Total** | **{len(report.findings)}** |")

    if report.metadata:
        lines += ["", "## Details de la cible", ""]
        for key, value in report.metadata.items():
            if value in ("", None, [], {}):
                continue
            lines.append(f"- **{key}** : {value}")

    lines += ["", "## Constats", ""]
    if not report.findings:
        lines.append("Aucun constat pour cette cible. ✅")
        return "\n".join(lines)

    lines += [
        "| Gravite | Regle | Constat | Preuve | Correctif |",
        "|---------|-------|---------|--------|-----------|",
    ]
    for finding in report.findings:
        lines.append(
            "| {sev} | `{rule}` | {message} | {evidence} | {fix} |".format(
                sev=finding.severity,
                rule=finding.rule_id,
                message=finding.message.replace("|", "\\|"),
                evidence=(finding.evidence or "-").replace("|", "\\|"),
                fix=(finding.remediation or "-").replace("|", "\\|"),
            )
        )
    return "\n".join(lines)


def render_html(report: Report) -> str:
    """Rapport HTML autonome (CSS embarque, aucune ressource externe)."""
    counts = report.counts()
    score = report.risk_score()
    cards = "".join(
        f'<div class="card"><span class="count sev-{sev.lower()}">{counts[sev]}</span>'
        f'<span class="label">{sev}</span></div>'
        for sev in SEVERITIES
    )
    rows: List[str] = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td><span class='badge sev-{finding.severity.lower()}'>{html.escape(finding.severity)}</span></td>"
            f"<td><code>{html.escape(finding.rule_id)}</code></td>"
            f"<td><strong>{html.escape(finding.title)}</strong>"
            f"<div class='msg'>{html.escape(finding.message)}</div>"
            f"<div class='ev'>{html.escape(finding.evidence or '—')}</div></td>"
            f"<td class='fix'>{html.escape(finding.remediation or '—')}</td>"
            "</tr>"
        )
    metadata_rows = "".join(
        f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in report.metadata.items()
        if value not in ("", None, [], {})
    )
    if rows:
        findings_table = (
            "<table class='findings'><thead><tr><th>Gravite</th><th>Regle</th>"
            "<th>Constat</th><th>Correctif</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
    else:
        findings_table = "<p class='clean'>✅ Aucun constat pour cette cible.</p>"

    template = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ — __TARGET__</title>
<style>
:root { color-scheme: dark; }
body { font-family: "Segoe UI", Roboto, Arial, sans-serif; margin:0; padding:32px; background:#0f172a; color:#e2e8f0; }
h1 { font-size:1.5rem; margin:0 0 4px; }
h2 { font-size:1.05rem; margin:28px 0 12px; }
.sub { color:#94a3b8; margin-bottom:24px; }
.cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }
.card { flex:1 1 110px; background:#111c33; border:1px solid #1e293b; border-radius:10px; padding:14px; text-align:center; }
.card .count { display:block; font-size:1.8rem; font-weight:700; }
.card .label { font-size:.72rem; letter-spacing:.08em; color:#94a3b8; }
.risk { background:#111c33; border:1px solid #1e293b; border-radius:10px; padding:16px 20px; margin-bottom:24px; }
table { width:100%; border-collapse:collapse; background:#111c33; border-radius:10px; overflow:hidden; }
th, td { padding:10px 12px; text-align:left; vertical-align:top; border-bottom:1px solid #1e293b; font-size:.9rem; }
thead th { background:#0b1424; color:#94a3b8; font-size:.72rem; letter-spacing:.06em; text-transform:uppercase; }
code { background:#0b1424; padding:2px 6px; border-radius:6px; color:#93c5fd; }
.badge { font-size:.7rem; font-weight:700; padding:3px 8px; border-radius:999px; color:#e2e8f0; background:#1e293b; }
.sev-critical { background:#7f1d1d; color:#fecaca; }
.sev-high { background:#9a3412; color:#fed7aa; }
.sev-medium { background:#854d0e; color:#fef08a; }
.sev-low { background:#155e75; color:#a5f3fc; }
.sev-info { background:#1e3a8a; color:#bfdbfe; }
.count.sev-critical, .count.sev-high, .count.sev-medium, .count.sev-low, .count.sev-info { background:transparent; }
.msg { color:#cbd5e1; margin-top:4px; }
.ev { color:#94a3b8; font-family:Consolas, monospace; font-size:.78rem; margin-top:4px; word-break:break-all; }
.fix { color:#bbf7d0; }
.clean { color:#86efac; font-weight:600; }
.meta th { width:220px; color:#94a3b8; font-weight:600; }
footer { margin-top:28px; color:#64748b; font-size:.8rem; }
</style>
</head>
<body>
<h1>__TITLE__</h1>
<div class="sub">Cible <strong>__TARGET__</strong> (__TYPE__) — genere le __DATE__</div>
<div class="risk">⚖️ Score de risque : <strong>__SCORE__/100</strong> — note <strong>__GRADE__</strong> (__LABEL__) — __TOTAL__ constat(s)</div>
<div class="cards">__CARDS__</div>
__FINDINGS__
<h2>Details de la cible</h2>
<table class="meta">__META__</table>
<footer>Rapport genere par Docker Security Scanner — outil d'audit educatif : aucun exploit n'est execute.</footer>
</body>
</html>
"""
    replacements = {
        "__TITLE__": TITLE,
        "__TARGET__": html.escape(report.target),
        "__TYPE__": html.escape(report.target_type),
        "__DATE__": html.escape(report.generated_at),
        "__SCORE__": str(score),
        "__GRADE__": report.grade(),
        "__LABEL__": risk_label(score),
        "__TOTAL__": str(len(report.findings)),
        "__CARDS__": cards,
        "__FINDINGS__": findings_table,
        "__META__": metadata_rows,
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template
