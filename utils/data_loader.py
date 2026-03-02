"""
Backend data loader — aucun code Streamlit ici.

Configuration via variables d'environnement (fichier .env) :

    DATA_SOURCE   : mock | parquet | csv | sql | elasticsearch  (défaut : mock)

    # Si DATA_SOURCE=parquet
    PARQUET_PATH  : chemin vers le fichier .parquet (relatif ou absolu)
                    Format attendu : colonne unique 'raw_log' séparée par ';'
                    timestamp;src_ip;dst_ip;proto;src_port;dst_port;policy_id;action;iface_in;iface_out;ttl

    # Si DATA_SOURCE=csv
    CSV_PATH      : chemin absolu vers le fichier CSV iptables

    # Si DATA_SOURCE=sql
    SQL_URL       : SQLAlchemy URL  (ex. postgresql://user:pass@host/db)
    SQL_QUERY     : requête SQL     (défaut : SELECT * FROM iptables_logs)

    # Si DATA_SOURCE=elasticsearch
    ES_URL        : URL du cluster  (ex. http://localhost:9200)
    ES_INDEX      : nom de l'index  (défaut : iptables-logs)
    ES_SIZE       : nb max de docs  (défaut : 10000)
"""

import os

import pandas as pd
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv facultatif

from utils.data_generator import generate_iptables_logs

REQUIRED_COLUMNS = {
    "timestamp", "src_ip", "dst_ip", "dst_port", "proto", "action", "policy_id"
}


# ---------------------------------------------------------------------------
# Validation & normalisation
# ---------------------------------------------------------------------------

def _validate(df: pd.DataFrame) -> pd.DataFrame:
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Colonnes manquantes dans la source de données : {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["dst_port"] = df["dst_port"].astype(int)
    return df.sort_values("timestamp").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Connecteurs par source
# ---------------------------------------------------------------------------

def _load_mock() -> pd.DataFrame:
    return generate_iptables_logs()


def _load_parquet() -> pd.DataFrame:
    path = os.getenv("PARQUET_PATH")
    if not path:
        raise EnvironmentError("PARQUET_PATH non défini dans les variables d'environnement.")
    raw = pd.read_parquet(path)
    # Colonne unique 'raw_log' : timestamp;src_ip;dst_ip;proto;src_port;dst_port;policy_id;action;iface_in;iface_out;ttl
    parsed = raw["raw_log"].str.strip().str.split(";", expand=True)
    parsed.columns = [
        "timestamp", "src_ip", "dst_ip", "proto",
        "src_port", "dst_port", "policy_id", "action",
        "interface_in", "interface_out", "ttl",
    ]
    # Normaliser l'action : DENY → Deny, PERMIT → Permit, supprimer lignes malformées
    parsed["action"] = parsed["action"].str.capitalize()
    parsed = parsed[parsed["action"].isin(["Deny", "Permit"])]
    return _validate(parsed.drop(columns=["src_port", "ttl"]))


def _load_csv() -> pd.DataFrame:
    path = os.getenv("CSV_PATH")
    if not path:
        raise EnvironmentError("CSV_PATH non défini dans les variables d'environnement.")
    return _validate(pd.read_csv(path, parse_dates=["timestamp"]))


def _load_sql() -> pd.DataFrame:
    from sqlalchemy import create_engine, text

    url = os.getenv("SQL_URL")
    if not url:
        raise EnvironmentError("SQL_URL non défini dans les variables d'environnement.")

    query = os.getenv("SQL_QUERY", "SELECT * FROM iptables_logs")
    engine = create_engine(url)
    with engine.connect() as conn:
        df = pd.read_sql(text(query), conn)
    return _validate(df)


def _load_elasticsearch() -> pd.DataFrame:
    from elasticsearch import Elasticsearch

    url   = os.getenv("ES_URL", "http://localhost:9200")
    index = os.getenv("ES_INDEX", "iptables-logs")
    size  = int(os.getenv("ES_SIZE", "10000"))

    es   = Elasticsearch(url)
    resp = es.search(index=index, body={"query": {"match_all": {}}, "size": size})
    rows = [hit["_source"] for hit in resp["hits"]["hits"]]
    return _validate(pd.DataFrame(rows))


_LOADERS = {
    "mock":          _load_mock,
    "parquet":       _load_parquet,
    "csv":           _load_csv,
    "sql":           _load_sql,
    "elasticsearch": _load_elasticsearch,
}


# ---------------------------------------------------------------------------
# Point d'entrée public — appelé par toutes les pages
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Chargement des données…", ttl=300)
def get_data() -> pd.DataFrame:
    """
    Charge les données depuis la source définie par DATA_SOURCE.
    Résultat mis en cache 5 min (ttl=300).
    Appelé par toutes les pages — ne pas modifier la logique de connexion ici.
    """
    source = os.getenv("DATA_SOURCE", "mock").lower()
    if source not in _LOADERS:
        raise ValueError(
            f"DATA_SOURCE='{source}' invalide. Valeurs acceptées : {list(_LOADERS)}"
        )
    return _LOADERS[source]()


def current_source() -> str:
    """Retourne le nom lisible de la source active."""
    return os.getenv("DATA_SOURCE", "mock").lower()
