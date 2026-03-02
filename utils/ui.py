"""Composants UI partagés entre toutes les pages."""

import pandas as pd
import streamlit as st

from utils.data_loader import current_source

_SOURCE_LABELS = {
    "mock":          ("🟡", "Données fictives"),
    "csv":           ("🟢", "CSV"),
    "sql":           ("🟢", "SQL"),
    "elasticsearch": ("🟢", "Elasticsearch"),
}

PAGE_CONFIG = dict(
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_sidebar(df: pd.DataFrame) -> pd.DataFrame:
    """Affiche le header + filtres, retourne le DataFrame filtré."""
    with st.sidebar:
        st.title("🛡️ OPSIE x SISE")
        st.caption("Visualisation et analyse de données de sécurité")

        icon, label = _SOURCE_LABELS.get(current_source(), ("⚪", current_source()))
        st.markdown(f"**Source** : {icon} `{label}`")
        st.divider()

        st.subheader("Filtres")
        proto_opts  = sorted(df["proto"].unique().tolist())
        action_opts = sorted(df["action"].unique().tolist())   # Permit / Deny

        proto_sel  = st.multiselect("Protocole", proto_opts,  default=proto_opts)
        action_sel = st.multiselect("Action",    action_opts, default=action_opts)

        st.divider()
        st.caption(f"{len(df):,} entrées totales")

    return df[df["proto"].isin(proto_sel) & df["action"].isin(action_sel)].copy()
