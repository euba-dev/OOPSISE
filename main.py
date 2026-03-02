"""
CHALLENGE OPSIE x SISE
Point d'entrée : streamlit run main.py
"""

import streamlit as st

from utils.data_loader import get_data, current_source
from utils.ui import PAGE_CONFIG

st.set_page_config(page_title="OPSIE x SISE — Accueil", **PAGE_CONFIG)

# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------

st.title("🛡️ CHALLENGE OPSIE x SISE")
st.subheader("Visualisation et analyse de données de sécurité réseau")
st.divider()

col1, col2 = st.columns([2, 1])

with col1:
    st.markdown(
        """
        Ce tableau de bord analyse les **logs iptables** exportés par les équipements OPSIE.
        Utilisez le menu de gauche pour naviguer entre les vues.

        | Page | Description |
        |---|---|
        | 📊 **Dashboard** | Vue d'ensemble : métriques, trafic horaire, top IPs |
        | 🔌 **Ports** | Analyse RFC 6056, ports les plus ciblés |
        | 📋 **Données** | Table brute, recherche et export CSV |
        | 🤖 **IA & ML** | Détection d'anomalies, NLP Mistral, Elasticsearch |
        """
    )

with col2:
    st.markdown("#### Configuration active")
    source = current_source()
    source_info = {
        "mock":          ("🟡", "Données fictives", "Générées localement pour le développement."),
        "csv":           ("🟢", "Fichier CSV",      "Lecture depuis `CSV_PATH`."),
        "sql":           ("🟢", "Base SQL",         "Connexion via `SQL_URL`."),
        "elasticsearch": ("🟢", "Elasticsearch",    "Index `ES_INDEX` sur `ES_URL`."),
    }
    icon, label, desc = source_info.get(source, ("⚪", source, ""))
    st.info(f"{icon} **{label}**\n\n{desc}")

    st.markdown("#### Changer de source")
    st.code(
        "# Dans votre fichier .env :\n"
        "DATA_SOURCE=csv\n"
        "CSV_PATH=/chemin/vers/logs.csv",
        language="bash",
    )

st.divider()

# Chargement anticipé pour afficher un résumé
try:
    df = get_data()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Entrées chargées", f"{len(df):,}")
    c2.metric("Plage temporelle",
              f"{df['timestamp'].min().strftime('%d/%m %H:%M')} → "
              f"{df['timestamp'].max().strftime('%d/%m %H:%M')}")
    c3.metric("IP sources uniques", f"{df['src_ip'].nunique():,}")
    c4.metric("Règles (policy_id)", f"{df['policy_id'].nunique()}")
except Exception as e:
    st.error(f"Impossible de charger les données : {e}")
