import streamlit as st

from utils.data_loader import get_data
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="Données — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("📋 Table de données brutes")

search = st.text_input(
    "Rechercher une IP source ou destination",
    placeholder="ex. 192.168.1."
)
if search:
    mask = (
        df["src_ip"].str.contains(search, na=False)
        | df["dst_ip"].str.contains(search, na=False)
    )
    df = df[mask]

st.caption(f"{len(df):,} entrées affichées")

st.dataframe(
    df,
    use_container_width=True,
    height=520,
    column_config={
        "timestamp":     st.column_config.DatetimeColumn("Timestamp", format="DD/MM/YYYY HH:mm:ss"),
        "src_ip":        st.column_config.TextColumn("IP Source"),
        "dst_ip":        st.column_config.TextColumn("IP Destination"),
        "dst_port":      st.column_config.NumberColumn("Port Dest.", format="%d"),
        "proto":         st.column_config.TextColumn("Proto"),
        "action":        st.column_config.TextColumn("Action"),
        "policy_id":     st.column_config.TextColumn("Règle"),
        "interface_in":  st.column_config.TextColumn("Iface In"),
        "interface_out": st.column_config.TextColumn("Iface Out"),
    },
)

st.download_button(
    label="⬇️ Exporter en CSV",
    data=df.to_csv(index=False).encode("utf-8"),
    file_name="logs_iptables_export.csv",
    mime="text/csv",
)
