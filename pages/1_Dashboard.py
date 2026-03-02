import streamlit as st
import plotly.express as px

from utils.data_loader import get_data
from utils.helpers import (
    compute_hourly_traffic, compute_deny_ratio, top_src_ips,
    top_permitted_ports_under_1024, external_ip_accesses,
)
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="Dashboard — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("📊 Vue d'ensemble du trafic réseau")

# ---------------------------------------------------------------------------
# Métriques (§1.5 point 4)
# ---------------------------------------------------------------------------
deny_pct   = compute_deny_ratio(df)
permit_pct = round(100 - deny_pct, 2)
n_external = len(external_ip_accesses(df))

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total flux",             f"{len(df):,}")
c2.metric("% Deny",                 f"{deny_pct} %", delta_color="inverse",
          delta=f"-{permit_pct} % Permit")
c3.metric("IP sources uniques",     f"{df['src_ip'].nunique():,}")
c4.metric("Règles actives",         f"{df['policy_id'].nunique()}")
c5.metric("IPs hors plan interne",  f"{n_external:,}")

st.divider()

# ---------------------------------------------------------------------------
# Trafic horaire + donut Permit/Deny
# ---------------------------------------------------------------------------
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Trafic par heure")
    hourly = compute_hourly_traffic(df)
    fig = px.bar(
        hourly, x="hour", y="count",
        labels={"hour": "Heure (UTC)", "count": "Flux"},
        color_discrete_sequence=["#3B82F6"],
    )
    fig.update_layout(
        xaxis=dict(dtick=1, tickvals=list(range(24))),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("Permit / Deny")
    counts = df["action"].value_counts().reset_index()
    counts.columns = ["action", "count"]
    fig = px.pie(
        counts, names="action", values="count", color="action",
        color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
        hole=0.45,
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=10, b=0),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2),
    )
    st.plotly_chart(fig, use_container_width=True)

st.divider()

# ---------------------------------------------------------------------------
# TOP 5 IPs sources (§1.5 point 4) + TOP 10 ports < 1024 Permit
# ---------------------------------------------------------------------------
col_a, col_b = st.columns(2)

with col_a:
    st.subheader("TOP 5 IP sources les plus émettrices")
    top5 = top_src_ips(df, n=5)
    fig = px.bar(
        top5, x="count", y="src_ip", orientation="h",
        labels={"src_ip": "IP source", "count": "Flux"},
        color="count", color_continuous_scale="Blues",
    )
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False, margin=dict(l=0, r=0, t=10, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)

with col_b:
    st.subheader("TOP 10 ports < 1024 autorisés (Permit)")
    top_ports = top_permitted_ports_under_1024(df, n=10)
    fig = px.bar(
        top_ports, x="dst_port", y="count",
        labels={"dst_port": "Port", "count": "Flux"},
        color_discrete_sequence=["#22C55E"],
    )
    fig.update_layout(
        xaxis_type="category",
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------------------
# IPs hors plan d'adressage interne
# ---------------------------------------------------------------------------
ext_df = external_ip_accesses(df)
if not ext_df.empty:
    st.subheader(f"Accès depuis IPs hors plan interne ({len(ext_df):,} flux)")
    ext_top = (
        ext_df.groupby(["src_ip", "action"], as_index=False)
        .size().rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
        .head(20)
    )
    fig = px.bar(
        ext_top, x="src_ip", y="count", color="action",
        color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
        labels={"src_ip": "IP source", "count": "Flux", "action": "Action"},
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)
