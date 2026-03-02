"""
Visualisation interactive par IP source (§1.5 point 3).
Scatter : chaque point = une IP source.
  x = nombre de destinations uniques contactées
  y = volume de flux total
  couleur = % Deny
  taille = volume de flux
"""

import streamlit as st
import plotly.express as px

from utils.data_loader import get_data
from utils.helpers import ip_traffic_summary
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="IP Explorer — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("🌐 Visualisation interactive par IP source")
st.caption("§1.5 point 3 — IP source · destinations contactées · flux Permit/Deny")

summary = ip_traffic_summary(df)

# ---------------------------------------------------------------------------
# Slider de navigation (filtre sur le volume de flux)
# ---------------------------------------------------------------------------
if not summary.empty:
    max_flows = int(summary["n_flows"].max())
    min_flows = int(summary["n_flows"].min())

    col_slider, col_stat = st.columns([3, 1])
    with col_slider:
        threshold = st.slider(
            "Afficher les IPs avec au moins N flux",
            min_value=min_flows, max_value=max_flows,
            value=min_flows, step=max(1, (max_flows - min_flows) // 50),
        )
    filtered = summary[summary["n_flows"] >= threshold]
    with col_stat:
        st.metric("IPs affichées", f"{len(filtered):,} / {len(summary):,}")

    # ---------------------------------------------------------------------------
    # Scatter principal
    # ---------------------------------------------------------------------------
    fig = px.scatter(
        filtered,
        x="n_dst",
        y="n_flows",
        color="deny_pct",
        size="n_flows",
        size_max=40,
        hover_name="src_ip",
        hover_data={
            "n_dst":    True,
            "n_flows":  True,
            "n_deny":   True,
            "n_permit": True,
            "deny_pct": ":.1f",
            "src_ip":   False,
        },
        labels={
            "n_dst":    "Nb destinations uniques",
            "n_flows":  "Volume de flux",
            "deny_pct": "% Deny",
        },
        color_continuous_scale="RdYlGn_r",
        range_color=[0, 100],
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
        coloraxis_colorbar=dict(title="% Deny"),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ---------------------------------------------------------------------------
    # Détail d'une IP sélectionnée
    # ---------------------------------------------------------------------------
    st.subheader("Détail par IP source")
    selected_ip = st.selectbox(
        "Sélectionner une IP",
        options=filtered.sort_values("n_flows", ascending=False)["src_ip"].tolist(),
    )
    if selected_ip:
        row = filtered[filtered["src_ip"] == selected_ip].iloc[0]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Flux total",       f"{row['n_flows']:,}")
        c2.metric("Destinations",     f"{row['n_dst']:,}")
        c3.metric("Flux Permit",      f"{row['n_permit']:,}")
        c4.metric("Flux Deny",        f"{row['n_deny']:,}",
                  delta=f"{row['deny_pct']} %", delta_color="inverse")

        ip_df = df[df["src_ip"] == selected_ip]
        col_l, col_r = st.columns(2)

        with col_l:
            dst_counts = (
                ip_df.groupby(["dst_ip", "action"], as_index=False)
                .size().rename(columns={"size": "count"})
                .sort_values("count", ascending=False)
                .head(10)
            )
            fig2 = px.bar(
                dst_counts, x="dst_ip", y="count", color="action",
                color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                labels={"dst_ip": "IP destination", "count": "Flux", "action": "Action"},
                title="Top 10 destinations",
            )
            fig2.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=30, b=0),
            )
            st.plotly_chart(fig2, use_container_width=True)

        with col_r:
            port_counts = (
                ip_df.groupby(["dst_port", "action"], as_index=False)
                .size().rename(columns={"size": "count"})
                .sort_values("count", ascending=False)
                .head(10)
            )
            fig3 = px.bar(
                port_counts, x="dst_port", y="count", color="action",
                color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                labels={"dst_port": "Port", "count": "Flux", "action": "Action"},
                title="Top 10 ports ciblés",
            )
            fig3.update_layout(
                xaxis_type="category",
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=30, b=0),
            )
            st.plotly_chart(fig3, use_container_width=True)
else:
    st.warning("Aucune donnée disponible avec les filtres actuels.")
