"""Docker / container security scanner - moteur d'analyse.

Modules :
    models           : modele de donnees (Finding, Report, scoring)
    rules            : catalogue des regles (rules/rules.json)
    secrets          : detection de secrets (regex + entropie)
    dockerfile_rules : analyse statique de Dockerfile
    image_analyzer   : analyse hors-ligne d'une image exportee (docker save)
    runtime_checks   : posture d'un conteneur via docker inspect
    reporters        : sorties console / json / html / markdown
"""

__version__ = "1.0.0"
__all__ = [
    "models",
    "rules",
    "secrets",
    "dockerfile_rules",
    "image_analyzer",
    "runtime_checks",
    "reporters",
]
