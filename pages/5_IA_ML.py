import streamlit as st

from utils.data_loader import get_data
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="IA & ML — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("🤖 IA & ML — Analyse avancée")

st.info(
    "En attente des données réelles et des clés API.\n\n"
    "Les fonctionnalités ci-dessous seront actives une fois `DATA_SOURCE`, "
    "`MISTRAL_API_KEY` et `ELASTICSEARCH_URL` configurés dans `.env`.",
    icon="⏳",
)

col1, col2 = st.columns(2)

with col1:
    with st.container(border=True):
        st.subheader("🔍 Détection d'anomalies")
        st.markdown(
            """
- **Isolation Forest** (scikit-learn) sur les patterns de ports et d'IPs
- Détection de scans de ports, brute-force SSH, DDoS
- Score d'anomalie par IP source
"""
        )
        st.button("Lancer la détection", disabled=True, key="btn_anomaly")

    with st.container(border=True):
        st.subheader("📈 Prédiction de trafic")
        st.markdown(
            """
- Régression sur fenêtre temporelle glissante
- Anticipation des pics de charge
- Alerte seuil configurable
"""
        )
        st.button("Entraîner le modèle", disabled=True, key="btn_predict")

with col2:
    with st.container(border=True):
        st.subheader("💬 Analyse NLP — Mistral AI")
        st.markdown(
            """
- Résumé automatique des événements de sécurité
- Classification des incidents par criticité
- Génération de rapports en langage naturel
"""
        )
        st.text_area(
            "Requête",
            placeholder="Ex : Résume les 10 dernières alertes critiques…",
            disabled=True,
        )
        st.button("Envoyer à Mistral", disabled=True, key="btn_mistral")

    with st.container(border=True):
        st.subheader("🗄️ Elasticsearch")
        st.markdown(
            """
- Indexation des logs pour recherche plein texte
- Agrégations temps-réel sur `ES_INDEX`
- Compatible Kibana
"""
        )
        st.button("Tester la connexion", disabled=True, key="btn_elastic")

st.divider()
st.caption(
    "Variables requises : `MISTRAL_API_KEY`, `ES_URL`, `ES_INDEX`. "
    "Voir `.env.example` pour le format."
)
