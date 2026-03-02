# OPSIE × SISE 2026 — Analyse de logs Firewall

Application web interactive de visualisation et d'analyse de logs iptables, développée dans le cadre du **Challenge OPSIE × SISE 2026** — Master SISE, Université Lumière Lyon 2.

---

## Fonctionnalités

- **Dashboard** : trafic horaire, heatmap, TOP IPs/ports, IPs externes, règles firewall
- **Données** : exploration des logs bruts, filtrage, export CSV
- **IA & ML** :
  - Clustering K-Means sur profils comportementaux agrégés par IP (méthode du coude + t-SNE 3D)
  - Détection d'anomalies Isolation Forest agrégé (score par IP)
  - Rapport de sécurité généré par **Mistral AI**
- Filtres partagés (période, heure, protocole, action) sur toutes les pages

---

## Prérequis

- Python 3.9+ (ou Docker)
- Conda (optionnel, recommandé)

---

## Installation

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
DATA_SOURCE=mock

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

```bash
docker compose up
```

L'application est accessible sur [http://localhost:8501](http://localhost:8501).

Pour reconstruire l'image après modification des dépendances :

```bash
docker compose up --build
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
│   ├── 1_Dashboard.py        # Tableau de bord
│   ├── 2_Donnees.py          # Exploration des logs bruts
│   └── 3_IA_ML.py            # K-Means, Isolation Forest, Mistral AI
├── utils/
│   ├── data_loader.py        # Connecteurs de données (mock/parquet/csv/sql/ES)
│   ├── data_generator.py     # Générateur de données fictives
│   ├── create_bdd.py         # Import CSV → SQLite
│   ├── helpers.py            # Fonctions métier
│   └── ui.py                 # Sidebar et configuration partagées
├── data/
│   ├── logs.db               # Base SQLite (générée par create_bdd.py)
│   └── echantillon_logs.csv  # Échantillon réel (non versionné)
├── .env                      # Configuration locale (non versionné)
├── .env.example              # Modèle de configuration
├── Dockerfile
├── docker-compose.yaml
└── requirements.txt
```

---

## Sources de données supportées

| `DATA_SOURCE` | Description | Variables requises |
|---|---|---|
| `mock` | Données générées (défaut) | — |
| `sql` | Base SQL (SQLite, PostgreSQL…) | `SQL_URL`, `SQL_QUERY` |
| `parquet` | Fichier Parquet | `PARQUET_PATH` |
| `csv` | Fichier CSV | `CSV_PATH` |
| `elasticsearch` | Index Elasticsearch | `ES_URL`, `ES_INDEX`, `ES_SIZE` |

---

## Dépendances principales

| Bibliothèque | Usage |
|---|---|
| `streamlit >= 1.36` | Interface web |
| `pandas` | Manipulation des données |
| `plotly` | Visualisations interactives |
| `scikit-learn` | K-Means, Isolation Forest, t-SNE |
| `mistralai` | Rapports IA en langage naturel |
| `sqlalchemy` | Connecteur SQL |
| `python-dotenv` | Chargement du `.env` |
