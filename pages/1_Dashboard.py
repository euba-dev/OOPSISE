import pandas as pd
import plotly.express as px
import streamlit as st

from utils.data_loader import get_data
from utils.helpers import (
    add_port_category,
    compute_deny_ratio,
    compute_hourly_traffic,
    external_ip_accesses,
    ip_traffic_summary,
    port_category_distribution,
    top_permitted_ports_under_1024,
    top_src_ips,
)
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="Dashboard — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("📊 Dashboard")

t1, t2, t3 = st.tabs(["Vue générale", "🔌 Ports & Protocoles", "🌐 IP Explorer"])

# =============================================================================
# TAB 1 — VUE GÉNÉRALE
# =============================================================================

with t1:
    deny_pct = compute_deny_ratio(df)
    n_ext    = len(external_ip_accesses(df))

    # Métriques — sans delta
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total flux",            f"{len(df):,}")
    c2.metric("Taux de Deny",          f"{deny_pct} %")
    c3.metric("IP sources uniques",    f"{df['src_ip'].nunique():,}")
    c4.metric("Règles actives",        f"{df['policy_id'].nunique()}")
    c5.metric("IPs hors plan interne", f"{n_ext:,}")

    # Aide à la lecture dynamique
    if deny_pct >= 25:
        st.error(
            f"🚨 **Taux de Deny critique ({deny_pct}%)** — Plus d'un quart des flux sont bloqués. "
            "Possible scan massif, brute-force ou DDoS. Investiguer les IPs sources immédiatement."
        )
    elif deny_pct >= 15:
        st.warning(
            f"⚠️ **Taux de Deny élevé ({deny_pct}%)** — Au-dessus du seuil standard (~15%). "
            "Surveiller les IPs sources et les ports ciblés."
        )
    else:
        st.success(
            f"✅ **Taux de Deny normal ({deny_pct}%)** — Activité réseau standard, aucune anomalie globale."
        )

    st.divider()

    # Trafic horaire + donut
    col_l, col_r = st.columns([2, 1])

    with col_l:
        st.subheader("Trafic par heure")
        hourly  = compute_hourly_traffic(df)
        peak_h  = int(hourly.loc[hourly["count"].idxmax(), "hour"])
        fig = px.bar(hourly, x="hour", y="count",
                     labels={"hour": "Heure (UTC)", "count": "Flux"},
                     color_discrete_sequence=["#3B82F6"])
        fig.update_layout(xaxis=dict(dtick=1, tickvals=list(range(24))),
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        peak_cnt = int(hourly.loc[hourly["hour"] == peak_h, "count"].values[0])
        st.caption(f"📌 Pic de trafic à **{peak_h}h** avec {peak_cnt:,} flux.")

    with col_r:
        st.subheader("Permit / Deny")
        counts = df["action"].value_counts().reset_index()
        counts.columns = ["action", "count"]
        fig = px.pie(counts, names="action", values="count", color="action",
                     color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"}, hole=0.45)
        fig.update_layout(margin=dict(l=0, r=0, t=10, b=0),
                          legend=dict(orientation="h", yanchor="bottom", y=-0.2))
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # TOP 5 IPs + TOP 10 ports <1024 Permit  (§1.5 pt 4)
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("TOP 5 IP sources les plus émettrices")
        top5 = top_src_ips(df, n=5)
        fig = px.bar(top5, x="count", y="src_ip", orientation="h",
                     labels={"src_ip": "IP source", "count": "Flux"},
                     color="count", color_continuous_scale="Blues")
        fig.update_layout(yaxis=dict(autorange="reversed"),
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          coloraxis_showscale=False, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        t1ip = top5.iloc[0]
        st.caption(f"📌 **{t1ip['src_ip']}** : {t1ip['count']:,} flux émis (plus active).")

    with col_b:
        st.subheader("TOP 10 ports < 1024 autorisés (Permit)")
        tp = top_permitted_ports_under_1024(df, n=10)
        if tp.empty:
            st.info("Aucun flux Permit sur ports < 1024 avec les filtres actuels.")
        else:
            fig = px.bar(tp, x="dst_port", y="count",
                         labels={"dst_port": "Port", "count": "Flux"},
                         color_discrete_sequence=["#22C55E"])
            fig.update_layout(xaxis_type="category",
                              plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                              margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(f"📌 Port **{int(tp.iloc[0]['dst_port'])}** : "
                       f"{int(tp.iloc[0]['count']):,} flux Permit.")

    # IPs hors plan interne  (§1.5 pt 4)
    ext_df = external_ip_accesses(df)
    if not ext_df.empty:
        st.subheader(f"Accès depuis IPs hors plan interne — {len(ext_df):,} flux")
        ext_agg = (ext_df.groupby(["src_ip", "action"], as_index=False)
                   .size().rename(columns={"size": "count"})
                   .sort_values("count", ascending=False).head(20))
        fig = px.bar(ext_agg, x="src_ip", y="count", color="action",
                     color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                     labels={"src_ip": "IP source", "count": "Flux"})
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        n_permit_ext = len(ext_df[ext_df["action"] == "Permit"])
        if n_permit_ext > 0:
            st.warning(f"⚠️ {n_permit_ext:,} flux **Permit** depuis des IPs hors plan interne — "
                       "À vérifier avec les règles de filtrage.")


# =============================================================================
# TAB 2 — PORTS & PROTOCOLES  (§1.5 pt 1)
# =============================================================================

with t2:
    df_p   = add_port_category(df)
    _COLORS = {"Well-known": "#6366F1", "Registered": "#F59E0B", "Dynamic/Private": "#10B981"}

    # Histogramme protocoles
    st.subheader("Flux par protocole et action")
    proto_cross = (df.groupby(["proto", "action"], as_index=False)
                   .size().rename(columns={"size": "count"}))
    fig = px.bar(proto_cross, x="proto", y="count", color="action", barmode="group",
                 color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                 labels={"proto": "Protocole", "count": "Flux"})
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, use_container_width=True)
    top_proto     = df.groupby("proto")["proto"].count().idxmax()
    deny_by_proto = df[df["action"] == "Deny"].groupby("proto").size()
    st.caption(
        f"📌 **{top_proto}** domine le trafic. "
        f"TCP : {deny_by_proto.get('TCP', 0):,} Deny · "
        f"UDP : {deny_by_proto.get('UDP', 0):,} Deny."
    )

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("RFC 6056 — Catégories de port")
        dist = port_category_distribution(df_p)
        fig = px.pie(dist, names="port_category", values="count",
                     color="port_category", color_discrete_map=_COLORS, hole=0.4)
        fig.update_layout(margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        st.caption(
            f"📌 Les ports **{dist.iloc[0]['port_category']}** dominent "
            f"({int(dist.iloc[0]['count']):,} flux)."
        )
        with st.expander("Définitions RFC 6056"):
            st.markdown(
                "| Plage | Catégorie | Exemples |\n|---|---|---|\n"
                "| 0 – 1023 | **Well-known** | HTTP (80), SSH (22), DNS (53) |\n"
                "| 1024 – 49151 | **Registered** | MySQL (3306), Redis (6379) |\n"
                "| 49152 – 65535 | **Dynamic/Private** | Ports éphémères |"
            )

    with col_b:
        st.subheader("TOP 15 ports ciblés")
        top_ports = (df_p.groupby(["dst_port", "port_category"], as_index=False)
                     .size().rename(columns={"size": "count"})
                     .sort_values("count", ascending=False).head(15))
        fig = px.bar(top_ports, x="dst_port", y="count", color="port_category",
                     labels={"dst_port": "Port", "count": "Flux", "port_category": "Catégorie"},
                     color_discrete_map=_COLORS)
        fig.update_layout(xaxis_type="category",
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        st.caption(f"📌 Port **{int(top_ports.iloc[0]['dst_port'])}** est le plus ciblé "
                   f"({int(top_ports.iloc[0]['count']):,} flux).")

    # Croisement catégorie × action
    st.subheader("Catégorie de port × Action firewall")
    cross = (df_p.groupby(["port_category", "action"], as_index=False)
             .size().rename(columns={"size": "count"}))
    fig = px.bar(cross, x="port_category", y="count", color="action", barmode="group",
                 color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                 labels={"port_category": "Catégorie", "count": "Flux"})
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# TAB 3 — IP EXPLORER  (§1.5 pt 3)
# =============================================================================

with t3:
    st.subheader("Visualisation interactive par IP source")
    st.caption("Chaque point = une IP source · Taille = volume de flux · Couleur = % Deny")

    summary = ip_traffic_summary(df)

    if summary.empty:
        st.warning("Aucune donnée avec les filtres actuels.")
    else:
        max_f = int(summary["n_flows"].max())
        min_f = int(summary["n_flows"].min())

        col_s, col_m = st.columns([3, 1])
        with col_s:
            threshold = st.slider("Afficher les IPs avec au moins N flux",
                                  min_value=min_f, max_value=max_f,
                                  value=min_f, step=max(1, (max_f - min_f) // 50))
        filtered = summary[summary["n_flows"] >= threshold]
        with col_m:
            st.metric("IPs affichées", f"{len(filtered):,} / {len(summary):,}")

        fig = px.scatter(
            filtered, x="n_dst", y="n_flows",
            color="deny_pct", size="n_flows", size_max=40,
            hover_name="src_ip",
            hover_data={"n_dst": True, "n_flows": True,
                        "n_deny": True, "n_permit": True,
                        "deny_pct": ":.1f", "src_ip": False},
            labels={"n_dst": "Destinations uniques",
                    "n_flows": "Volume de flux", "deny_pct": "% Deny"},
            color_continuous_scale="RdYlGn_r", range_color=[0, 100],
        )
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

        high_deny = filtered[filtered["deny_pct"] >= 50]
        if not high_deny.empty:
            st.warning(
                f"⚠️ **{len(high_deny)} IP(s)** avec >50% de Deny : "
                + ", ".join(f"`{ip}`" for ip in high_deny.head(5)["src_ip"])
                + (" …" if len(high_deny) > 5 else "")
                + " — Comportement potentiellement malveillant."
            )

        st.divider()
        st.subheader("Détail d'une IP")
        selected = st.selectbox(
            "Sélectionner une IP",
            filtered.sort_values("n_flows", ascending=False)["src_ip"].tolist(),
        )
        if selected:
            row = filtered[filtered["src_ip"] == selected].iloc[0]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Flux total",   f"{row['n_flows']:,}")
            c2.metric("Destinations", f"{row['n_dst']:,}")
            c3.metric("Permit",       f"{row['n_permit']:,}")
            c4.metric("Deny",         f"{row['n_deny']:,}")

            ip_df = df[df["src_ip"] == selected]
            cl, cr = st.columns(2)

            with cl:
                dst_c = (ip_df.groupby(["dst_ip", "action"], as_index=False)
                         .size().rename(columns={"size": "count"})
                         .sort_values("count", ascending=False).head(10))
                fig2 = px.bar(dst_c, x="dst_ip", y="count", color="action",
                              color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                              labels={"dst_ip": "IP dest.", "count": "Flux"},
                              title="Top 10 destinations")
                fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                   margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig2, use_container_width=True)

            with cr:
                port_c = (ip_df.groupby(["dst_port", "action"], as_index=False)
                          .size().rename(columns={"size": "count"})
                          .sort_values("count", ascending=False).head(10))
                fig3 = px.bar(port_c, x="dst_port", y="count", color="action",
                              color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                              labels={"dst_port": "Port", "count": "Flux"},
                              title="Top 10 ports ciblés")
                fig3.update_layout(xaxis_type="category",
                                   plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                   margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig3, use_container_width=True)
