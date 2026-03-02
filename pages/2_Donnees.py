import streamlit as st

from utils.data_loader import get_data
from utils.ui import render_sidebar

_MAX_ROWS_DEFAULT = 500
_MAX_ROWS_OPTIONS = [200, 500, 1_000, 5_000]

df = render_sidebar(get_data())

st.header("📋 Table de données brutes")

search = st.text_input("Rechercher une IP source ou destination",
                       placeholder="ex. 192.168.1.")
if search:
    mask = (df["src_ip"].str.contains(search, na=False)
            | df["dst_ip"].str.contains(search, na=False))
    df = df[mask]

# ── Gestion du volume d'affichage ─────────────────────────────────────────────
n_total = len(df)

col_info, col_limit = st.columns([3, 1])
with col_limit:
    max_rows = st.selectbox(
        "Lignes affichées (max)",
        options=_MAX_ROWS_OPTIONS,
        index=_MAX_ROWS_OPTIONS.index(_MAX_ROWS_DEFAULT),
        help=(
            "Limiter le nombre de lignes affichées améliore les performances. "
            "L'export CSV ci-dessous contient toujours l'intégralité des données filtrées."
        ),
    )

df_display = df.head(max_rows)

with col_info:
    if n_total == 0:
        st.warning("Aucune entrée ne correspond aux filtres sélectionnés.")
    elif n_total > max_rows:
        st.info(
            f"Affichage des **{max_rows:,}** premières lignes sur **{n_total:,}** entrées filtrées. "
            f"Augmentez la limite ou exportez le CSV pour tout voir."
        )
    else:
        st.caption(f"{n_total:,} entrées affichées.")

st.dataframe(
    df_display, use_container_width=True, height=520,
    column_config={
        "timestamp":     st.column_config.DatetimeColumn("Timestamp",       format="DD/MM/YYYY HH:mm:ss"),
        "src_ip":        st.column_config.TextColumn("IP Source"),
        "dst_ip":        st.column_config.TextColumn("IP Destination"),
        "dst_port":      st.column_config.NumberColumn("Port",              format="%d"),
        "proto":         st.column_config.TextColumn("Protocole"),
        "action":        st.column_config.TextColumn("Décision"),
        "policy_id":     st.column_config.TextColumn("Règle"),
        "interface_in":  st.column_config.TextColumn("Interface entrante"),
        "interface_out": st.column_config.TextColumn("Interface sortante"),
    },
)

st.download_button(
    "⬇️ Exporter toutes les entrées filtrées en CSV",
    data=df.to_csv(index=False).encode("utf-8"),
    file_name="logs_iptables_export.csv",
    mime="text/csv",
    help=f"Le fichier contiendra les {n_total:,} entrées filtrées (pas seulement celles affichées).",
)
