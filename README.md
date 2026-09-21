# 🐳 Docker Security Scanner

Audit de sécurité **hors-ligne** des Dockerfiles, images (`docker save`) et conteneurs (`docker inspect`).

- ✅ **Zéro dépendance externe** — bibliothèque standard Python uniquement (3.9+)
- ✅ **50 contrôles** : Dockerfile (CIS Benchmark), image (secrets, couches, setuid...), runtime (`--privileged`, socket Docker, capabilities...)
- ✅ **Secrets toujours masqués** dans les rapports (jamais de valeur en clair)
- ✅ **4 formats** : console couleur, JSON, HTML autonome, Markdown
- ✅ **Prêt pour la CI** : `--fail-on high`, codes de sortie exploitables

## 🚀 Installation

```bash
git clone https://github.com/Believe-sec-io/docker-security-scanner.git
cd docker-security-scanner
# Aucune installation requise (stdlib uniquement). Optionnel :
pip install -r requirements.txt  # ne contient que pytest pour les tests
```

## 📖 Utilisation

```bash
# 1. Analyser un Dockerfile
python docker_scanner.py --dockerfile examples/insecure/Dockerfile

# 2. Analyser tous les Dockerfiles d'un projet
python docker_scanner.py . --format markdown -o rapport.md

# 3. Analyser une image exportée (sans démon Docker)
docker save mon-app:1.0 -o mon-app.tar
python docker_scanner.py --image-tar mon-app.tar --format html -o rapport.html

# 4. Analyser une image locale (nécessite Docker)
python docker_scanner.py --image mon-app:1.0 --fail-on high

# 5. Auditer un conteneur en cours d'exécution (nécessite Docker)
python docker_scanner.py --container mon-conteneur

# 6. Voir le catalogue des 50 règles
python docker_scanner.py --list-rules
```

## ⚙️ Options

| Option | Rôle |
|---|---|
| `-f, --format {console,json,html,markdown}` | Format du rapport (défaut : console) |
| `-o, --output FICHIER` | Écrire le rapport dans un fichier |
| `--min-severity {critical,high,medium,low,info}` | Seuil minimal affiché |
| `--ignore DS-DF-003,DS-IMG-017` | Règles à exclure |
| `--fail-on {critical,high,medium,low,info,never}` | Code de sortie 1 si seuil atteint (CI) |
| `--context DOSSIER` | Contexte de build (vérification `.dockerignore`) |
| `--max-size-mb 1500` / `--max-layers 20` | Seuils image volumineuse / trop de couches |
| `--skip-layer-content` | Ne pas inspecter le contenu des couches |
| `--no-color` / `--quiet` | Sortie sans couleur / silencieuse |

Exemple CI (GitHub Actions) :

```yaml
- run: python docker_scanner.py . --fail-on high --format json -o scan.json
```

## 📚 Catalogue des règles (50)

| Famille | IDs | Exemples |
|---|---|---|
| Dockerfile (19) | `DS-DF-001` → `DS-DF-019` | image `:latest`, `USER root`, secret en `ENV`, `curl … \| sh`, `ADD` d'URL, `chmod 777`, `sudo`, `EXPOSE 22`, EOL (Ubuntu 18.04...), `.dockerignore` absent |
| Image (18) | `DS-IMG-001` → `DS-IMG-018` | user root, pas de HEALTHCHECK, secret en ENV, port sensible, setuid, `o+w`, `.env`/`.ssh` embarqués, taille/couches excessives |
| Runtime (12) | `DS-RT-001` → `DS-RT-012` | `--privileged`, `--pid=host`, capabilities `SYS_ADMIN`, pas de limite mémoire/CPU, socket Docker monté, rootfs inscriptible, port DB exposé |
| Générique (1) | `DS-GEN-001` | démon Docker indisponible (mode dégradé informatif) |

Chaque règle est documentée dans `rules/rules.json` (titre, gravité, remédiation, références CIS/OWASP).

## 🧪 Tests

```bash
python -m pytest tests/ -q
# ou sans pytest :
python -m unittest discover -s tests -v
```

Couverture : catalogue (cohérence code ↔ JSON), secrets (motifs, placeholders, entropie), Dockerfile (exemples `secure` vs `insecure`), image (archive synthétique construite en mémoire), runtime (`docker inspect` simulé), reporters (4 formats).

## 📁 Arborescence

```
docker-security-scanner/
├── docker_scanner.py          # CLI (argparse, détection de cible, sortie CI)
├── rules/rules.json           # Source de vérité : 51 règles documentées
├── scanner/
│   ├── models.py              # Finding, Report, score 0-100, note A-F
│   ├── rules.py               # Chargement catalogue + make_finding()
│   ├── secrets.py             # Regex secrets + entropie de Shannon + redact()
│   ├── dockerfile_rules.py    # 20 règles Dockerfile (statique, sans pull)
│   ├── image_analyzer.py      # 21 règles image (tar docker save / OCI)
│   ├── runtime_checks.py      # 12 règles conteneur (docker inspect)
│   └── reporters.py           # console / json / html / markdown
├── examples/
│   ├── insecure/Dockerfile    # Déclenche ≥14 règles (démo)
│   └── secure/                # Multi-stage durci (zéro HIGH/CRITICAL)
└── tests/                     # 6 fichiers de tests unitaires
```

## ⚖️ Score de risque

Poids : CRITICAL 40, HIGH 15, MEDIUM 6, LOW 2, INFO 0 (plafond 100).
Notes : A (0) → B (≤10) → C (≤25) → D (≤45) → F (>45).

## ⚠️ Avertissement

Outil d'audit **éducatif** : analyse statique, aucun exploit exécuté. Complétez avec un scanner CVE (Trivy, Grype) pour les vulnérabilités connues des paquets.

## 📄 Licence

MIT — voir `LICENSE`.
