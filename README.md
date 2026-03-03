# OPSIE × SISE 2026 — Analyse de logs Firewall

Application web interactive de visualisation et d'analyse de logs iptables, développée dans le cadre du **Challenge OPSIE × SISE 2026** — Master SISE, Université Lumière Lyon 2.

---

## Fonctionnalités

- **Dashboard** : trafic horaire, heatmap, TOP IPs/ports, IPs externes, règles firewall, analyse des priorités métier par Mistral AI
- **Données** : exploration des logs bruts, filtrage, export CSV
- **IA & ML** :
  - Clustering K-Means sur profils comportementaux agrégés par IP (méthode du coude + t-SNE 3D)
  - Détection d'anomalies Isolation Forest agrégé (score par IP, contamination fixée à 5 %)
  - Rapport de sécurité généré par **Mistral AI** (choix du modèle : small / medium / large)
- Filtres partagés (période, heure, protocole, action, catégorie de port RFC 6056) sur toutes les pages
- Sélecteur de source de données dans la sidebar (données fictives ↔ données réelles)

---

## Prérequis

- Python 3.11+ (ou Docker)
- Conda (optionnel, recommandé)

---

## Installation locale

### Option 1 — Conda (recommandé)

```bash
conda create -n challenge_oopsise python=3.11
conda activate challenge_oopsise
pip install -r requirements.txt
```

### Option 2 — pip classique

```bash
pip install -r requirements.txt
```

---

## Configuration

Copier le fichier d'exemple et renseigner les valeurs :

```bash
cp .env.example .env
```

Éditer `.env` :

```env
# Source de données : mock | parquet | csv | sql | elasticsearch
DATA_SOURCE=sql

# Si DATA_SOURCE=sql (SQLite)
SQL_URL=sqlite:///data/logs.db
SQL_QUERY=SELECT * FROM iptables_logs

# Si DATA_SOURCE=parquet
PARQUET_PATH=data/logs_export.parquet

# Clé API Mistral (onglet IA & ML)
MISTRAL_API_KEY=votre_clé_ici
```

> `.env` est dans `.gitignore` — ne jamais committer les secrets.

---

## Lancement

```bash
streamlit run main.py
```

L'application est accessible sur [http://localhost:8501](http://localhost:8501).

Avec Conda :

```bash
conda run -n challenge_oopsise streamlit run main.py
```

---

## Lancement avec Docker

Trois méthodes sont disponibles selon votre contexte.

---

### Méthode A — Docker Compose (recommandée, depuis le code source)

La méthode la plus simple si vous avez le dossier `OOPSISE/` en local. Docker Compose charge automatiquement le fichier `.env` (clé Mistral incluse).

**1. Lancer l'application :**

```bash
cd OOPSISE/
docker compose up
```

**2. Reconstruire l'image après modification des dépendances :**

```bash
docker compose up --build
```

**3. Accéder à l'application :**

[http://localhost:8501](http://localhost:8501)

---

### Méthode B — docker build + docker run (depuis le code source, sans Compose)

Alternative si Docker Compose n'est pas disponible.

**1. Builder l'image :**

```bash
cd OOPSISE/
docker build -t oopsise-app:latest .
```

**2. Lancer le conteneur :**

```bash
docker run -p 8501:8501 oopsise-app:latest
```

**3. Avec une clé Mistral (optionnel) :**

```bash
docker run -p 8501:8501 -e MISTRAL_API_KEY=sk-... oopsise-app:latest
```

**4. Accéder à l'application :**

[http://localhost:8501](http://localhost:8501)

---

### Méthode C — Charger l'image depuis le fichier exporté (`oopsise-app.tar.gz`)

Cette méthode ne nécessite **pas** le code source — uniquement Docker et le fichier `.tar.gz`.

**1. Charger l'image dans Docker :**

```bash
docker load < oopsise-app.tar.gz
```

**2. Lancer le conteneur :**

```bash
docker run -p 8501:8501 oopsise-app:latest
```

**3. Avec une clé Mistral (optionnel) :**

```bash
docker run -p 8501:8501 -e MISTRAL_API_KEY=sk-... oopsise-app:latest
```

**4. Accéder à l'application :**

[http://localhost:8501](http://localhost:8501)

---

### Choix de la source de données dans Docker

L'image embarque la base SQLite (`data/logs.db`). Une fois l'application lancée, le **sélecteur de source** est disponible directement dans la sidebar :

- `🟢 Données extraites` — logs réels issus de la base SQLite
- `🟡 Données fictives` — données générées aléatoirement

Pas besoin de relancer le conteneur pour basculer : le changement se fait en un clic dans l'interface.

Par défaut, le conteneur démarre sur les **données réelles** (`DATA_SOURCE=sql`). Pour démarrer sur les données fictives :

```bash
docker run -p 8501:8501 -e DATA_SOURCE=mock oopsise-app:latest
```

---

## Import des données réelles (SQLite)

Si vous disposez du fichier `echantillon_logs.csv`, placez-le dans `data/` puis exécutez :

```bash
python utils/create_bdd.py
```

Ce script :
1. Lit le CSV brut (colonnes : `month`, `day`, `time`, `host`, `action`, `rule`, `src`, `dst`, `proto`, `spt`, `dpt`)
2. Reconstruit le timestamp
3. Normalise les colonnes et les valeurs d'action (`PERMIT` → `Permit`, `DENY` → `Deny`)
4. Insère les données dans `data/logs.db`

Activer ensuite la source SQL dans `.env` :

```env
DATA_SOURCE=sql
SQL_URL=sqlite:///data/logs.db
SQL_QUERY=SELECT * FROM iptables_logs
```

---

## Structure du projet

```
OOPSISE/
├── main.py                   # Point d'entrée, page d'accueil, navigation
├── pages/
│   ├── 1_Dashboard.py        # Tableau de bord + analyse Mistral des priorités
│   ├── 2_Donnees.py          # Exploration des logs bruts
│   └── 3_IA_ML.py            # K-Means, Isolation Forest, Mistral AI
├── utils/
│   ├── data_loader.py        # Connecteurs de données (mock/parquet/csv/sql/ES)
│   ├── data_generator.py     # Générateur de données fictives
│   ├── create_bdd.py         # Import CSV → SQLite
│   ├── helpers.py            # Fonctions métier
│   └── ui.py                 # Sidebar, filtres et sélecteur de source
├── data/
│   ├── logs.db               # Base SQLite (générée par create_bdd.py)
│   └── echantillon_logs.csv  # Échantillon réel (non versionné)
├── .env                      # Configuration locale (non versionné)
├── .env.example              # Modèle de configuration
├── Dockerfile                # Image Python 3.11-slim
├── .dockerignore             # Exclut .env, cache, parquet volumineux
├── docker-compose.yaml       # Lancement simplifié avec chargement du .env
└── requirements.txt
```

---

## Sources de données supportées

| `DATA_SOURCE` | Description | Variables requises |
|---|---|---|
| `mock` | Données générées (défaut dev) | — |
| `sql` | Base SQL (SQLite, PostgreSQL…) | `SQL_URL`, `SQL_QUERY` |
| `parquet` | Fichier Parquet | `PARQUET_PATH` |
| `csv` | Fichier CSV | `CSV_PATH` |
| `elasticsearch` | Index Elasticsearch | `ES_URL`, `ES_INDEX`, `ES_SIZE` |

---

## Dépendances principales

| Bibliothèque | Usage |
|---|---|
| `streamlit >= 1.36` | Interface web multipage |
| `pandas` | Manipulation des données |
| `plotly` | Visualisations interactives |
| `scikit-learn` | K-Means, Isolation Forest, t-SNE |
| `mistralai >= 1.0.0` | Rapports IA en langage naturel |
| `sqlalchemy` | Connecteur SQL |
| `python-dotenv` | Chargement du `.env` |
