"""
CHALLENGE OPSIE x SISE 2026 — Point d'entrée
streamlit run main.py
"""

import streamlit as st

from utils.ui import PAGE_CONFIG

st.set_page_config(page_title="OPSIE x SISE 2026", **PAGE_CONFIG)

pg = st.navigation([
    st.Page("pages/accueil.py",     title="Accueil",   icon="🏠"),
    st.Page("pages/1_Dashboard.py", title="Dashboard", icon="📊"),
    st.Page("pages/2_Donnees.py",   title="Données",   icon="📋"),
    st.Page("pages/3_IA_ML.py",     title="IA & ML",   icon="🤖"),
])
pg.run()
