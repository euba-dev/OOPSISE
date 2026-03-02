"""Composants UI partagés entre toutes les pages."""

import pandas as pd
import streamlit as st

from utils.data_loader import current_source
from utils.helpers import classify_port

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

        _col_title, _col_reset = st.columns([3, 1])
        with _col_title:
            st.subheader("Filtres")
        with _col_reset:
            st.write("")
            if st.button("↺", help="Réinitialiser tous les filtres", use_container_width=True):
                for _k in ["_flt_date", "_flt_hour", "_flt_proto", "_flt_action", "_flt_ports"]:
                    st.session_state.pop(_k, None)
                st.rerun()

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
                key="_flt_date",
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
            key="_flt_hour",
        )
        mask_hour = (ts.dt.hour >= h_start) & (ts.dt.hour <= h_end)

        # ── Filtres métier ─────────────────────────────────────────────────────
        proto_opts  = sorted(df["proto"].unique().tolist())
        action_opts = sorted(df["action"].unique().tolist())

        proto_sel  = st.multiselect("Protocole", proto_opts,  default=proto_opts,  key="_flt_proto")
        action_sel = st.multiselect("Action",    action_opts, default=action_opts, key="_flt_action")

        # ── Filtre RFC 6056 (catégorie de port) ────────────────────────────────
        _PORT_CATS = {
            "Well-known":      "🟣 Well-known (0–1023)",
            "Registered":      "🟡 Registered (1024–49151)",
            "Dynamic/Private": "🟢 Dynamic/Private (49152–65535)",
        }
        port_cat_sel = st.multiselect(
            "Catégorie de port (RFC 6056)",
            options=list(_PORT_CATS.values()),
            default=list(_PORT_CATS.values()),
            help=(
                "Filtrer selon les plages de ports définies par la RFC 6056 : "
                "Well-known (0–1023), Registered (1024–49151), Dynamic/Private (49152–65535)."
            ),
            key="_flt_ports",
        )
        selected_cat_keys = [k for k, v in _PORT_CATS.items() if v in port_cat_sel]
        mask_port = df["dst_port"].apply(classify_port).isin(selected_cat_keys)

        # ── Résumé volume ──────────────────────────────────────────────────────
        st.divider()
        mask_all = (
            mask_date
            & mask_hour
            & df["proto"].isin(proto_sel)
            & df["action"].isin(action_sel)
            & mask_port
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
