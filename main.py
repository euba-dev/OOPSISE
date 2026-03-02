"""
CHALLENGE OPSIE x SISE 2026 — Page d'accueil
streamlit run main.py
"""

import streamlit as st

from utils.data_loader import current_source, get_data
from utils.ui import PAGE_CONFIG

st.set_page_config(page_title="Accueil — OPSIE x SISE", **PAGE_CONFIG)

df = get_data()

st.title("🛡️ OPSIE x SISE — Analyse Firewall")
st.caption("Visualisation et analyse de logs iptables · Challenge 2026")
st.divider()

# ── Source active ─────────────────────────────────────────────────────────────
source_info = {
    "mock":          ("🟡", "Données fictives",  "Générées localement pour le développement."),
    "parquet":       ("🟢", "Fichier Parquet",   "Lecture depuis `PARQUET_PATH`."),
    "csv":           ("🟢", "Fichier CSV",       "Lecture depuis `CSV_PATH`."),
    "sql":           ("🟢", "Base SQL",          "Connexion via `SQL_URL`."),
    "elasticsearch": ("🟢", "Elasticsearch",     "Index `ES_INDEX` sur `ES_URL`."),
}
icon, label, desc = source_info.get(current_source(), ("⚪", current_source(), ""))

col1, col2 = st.columns([2, 1])

with col1:
    st.markdown(
        """
| Page | Contenu |
|---|---|
| 📊 **Dashboard** | Métriques, trafic horaire, RFC 6056, IP Explorer |
| 📋 **Données** | Table brute, recherche, export CSV |
| 🤖 **IA & ML** | Isolation Forest + Mistral AI |
"""
    )
    st.markdown("##### Lancer l'app")
    st.code("streamlit run main.py", language="bash")
    st.markdown("##### Changer de source de données")
    st.code(
        "# .env\nDATA_SOURCE=parquet\nPARQUET_PATH=logs_export.parquet",
        language="bash",
    )

with col2:
    st.info(f"{icon} **{label}**\n\n{desc}")
    st.markdown("##### Clé Mistral AI")
    st.code("# .env\nMISTRAL_API_KEY=votre_clé", language="bash")

st.divider()

# ── Résumé des données chargées ───────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Entrées chargées",   f"{len(df):,}")
c2.metric("Plage temporelle",
          f"{df['timestamp'].min().strftime('%d/%m %H:%M')} → "
          f"{df['timestamp'].max().strftime('%d/%m %H:%M')}")
c3.metric("IP sources uniques", f"{df['src_ip'].nunique():,}")
c4.metric("Règles actives",     f"{df['policy_id'].nunique()}")
