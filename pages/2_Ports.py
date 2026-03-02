import streamlit as st
import plotly.express as px

from utils.data_loader import get_data
from utils.helpers import add_port_category, port_category_distribution
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="Ports — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())
df = add_port_category(df)

st.header("🔌 Analyse des ports de destination (RFC 6056)")

_COLORS = {
    "Well-known":      "#6366F1",
    "Registered":      "#F59E0B",
    "Dynamic/Private": "#10B981",
}

# ---------------------------------------------------------------------------
# Répartition RFC + top 15 ports
# ---------------------------------------------------------------------------
col_a, col_b = st.columns([1, 1])

with col_a:
    st.subheader("Répartition par catégorie")
    dist = port_category_distribution(df)
    fig = px.pie(
        dist, names="port_category", values="count",
        color="port_category", color_discrete_map=_COLORS,
        hole=0.4,
    )
    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, use_container_width=True)

    with st.expander("Définitions RFC 6056"):
        st.markdown(
            """
| Plage | Catégorie | Exemples |
|---|---|---|
| 0 – 1023 | **Well-known** | HTTP (80), HTTPS (443), SSH (22), DNS (53) |
| 1024 – 49151 | **Registered** | MySQL (3306), PostgreSQL (5432), Redis (6379) |
| 49152 – 65535 | **Dynamic/Private** | Ports éphémères, connexions clients |
"""
        )

with col_b:
    st.subheader("Top 15 ports ciblés")
    top_ports = (
        df.groupby(["dst_port", "port_category"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
        .head(15)
    )
    fig = px.bar(
        top_ports, x="dst_port", y="count", color="port_category",
        labels={"dst_port": "Port", "count": "Flux", "port_category": "Catégorie"},
        color_discrete_map=_COLORS,
    )
    fig.update_layout(
        xaxis_type="category",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------------------
# Croisement catégorie × action
# ---------------------------------------------------------------------------
st.subheader("Catégorie de port × Action firewall")
cross = (
    df.groupby(["port_category", "action"], as_index=False)
    .size()
    .rename(columns={"size": "count"})
)
fig = px.bar(
    cross, x="port_category", y="count", color="action",
    barmode="group",
    color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
    labels={"port_category": "Catégorie", "count": "Flux", "action": "Action"},
)
fig.update_layout(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    margin=dict(l=0, r=0, t=10, b=0),
)
st.plotly_chart(fig, use_container_width=True)
