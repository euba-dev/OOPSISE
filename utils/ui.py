"""Composants UI partagés entre toutes les pages."""

import pandas as pd
import streamlit as st

from utils.data_loader import current_source

_SOURCE_LABELS = {
    "mock":          ("🟡", "Données fictives"),
    "parquet":       ("🟢", "Parquet"),
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
    """Affiche le header + filtres temporels + filtres métier, retourne le DataFrame filtré."""
    with st.sidebar:
        st.title("🛡️ OPSIE x SISE")
        st.caption("Visualisation et analyse de données de sécurité")

        icon, label = _SOURCE_LABELS.get(current_source(), ("⚪", current_source()))
        st.markdown(f"**Source** : {icon} `{label}`")
        st.divider()

        st.subheader("Filtres")

        # ── Filtres temporels ──────────────────────────────────────────────────
        ts = df["timestamp"]
        min_date = ts.min().date()
        max_date = ts.max().date()

        if min_date != max_date:
            date_range = st.date_input(
                "📅 Période",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date,
                help="Sélectionnez une plage de dates pour restreindre l'analyse.",
            )
            if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
                d_start, d_end = date_range
            else:
                d_start, d_end = min_date, max_date
            mask_date = (ts.dt.date >= d_start) & (ts.dt.date <= d_end)
        else:
            st.caption(f"📅 Journée : {min_date.strftime('%d/%m/%Y')}")
            mask_date = pd.Series(True, index=df.index)

        h_start, h_end = st.slider(
            "⏰ Plage horaire",
            0, 23, (0, 23),
            format="%dh",
            help=(
                "Filtrer les connexions selon l'heure de la journée (UTC). "
                "Utile pour isoler le trafic nocturne ou les heures de pointe."
            ),
        )
        mask_hour = (ts.dt.hour >= h_start) & (ts.dt.hour <= h_end)

        # ── Filtres métier ─────────────────────────────────────────────────────
        proto_opts  = sorted(df["proto"].unique().tolist())
        action_opts = sorted(df["action"].unique().tolist())

        proto_sel  = st.multiselect("Protocole", proto_opts,  default=proto_opts)
        action_sel = st.multiselect("Action",    action_opts, default=action_opts)

        # ── Résumé volume ──────────────────────────────────────────────────────
        st.divider()
        mask_all = (
            mask_date
            & mask_hour
            & df["proto"].isin(proto_sel)
            & df["action"].isin(action_sel)
        )
        n_filtered = int(mask_all.sum())
        n_total    = len(df)

        st.caption(f"**{n_filtered:,}** entrées affichées sur {n_total:,}")

        if n_filtered == 0:
            st.error("❌ Aucune donnée ne correspond aux filtres sélectionnés.")
        elif n_filtered > 20_000:
            st.warning(
                f"⚠️ {n_filtered:,} entrées — volume important. "
                "Les graphiques peuvent être lents à s'afficher."
            )

    return df[mask_all].copy()
