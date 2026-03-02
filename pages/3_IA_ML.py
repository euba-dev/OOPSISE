import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Charger .env explicitement depuis la racine du projet
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

from utils.data_loader import get_data
from utils.helpers import compute_deny_ratio, external_ip_accesses, top_src_ips
from utils.ui import PAGE_CONFIG, render_sidebar

st.set_page_config(page_title="IA & ML — OPSIE x SISE", **PAGE_CONFIG)

df = render_sidebar(get_data())

st.header("🤖 IA & ML — Analyse avancée")

tab_insights, tab_if, tab_mistral = st.tabs([
    "⚡ Insights automatiques",
    "🔍 Isolation Forest",
    "💬 Mistral AI",
])


# =============================================================================
# TAB 1 — INSIGHTS AUTOMATIQUES (aucune API, résultats immédiats)
# =============================================================================

with tab_insights:
    st.markdown("Détection de patterns suspects calculée directement sur les données — sans API externe.")

    if df.empty:
        st.warning("Aucune donnée avec les filtres actuels.")
    else:
        deny_pct = compute_deny_ratio(df)
        df_h = df.copy()
        df_h["hour"] = df_h["timestamp"].dt.hour

        # ── KPIs ──────────────────────────────────────────────────────────────
        c1, c2, c3, c4 = st.columns(4)

        # IP la plus suspecte : deny_ratio le plus élevé avec >20 flux
        ip_stats = (df.groupby("src_ip")
                    .agg(n_flows=("dst_ip", "count"),
                         n_deny=("action", lambda x: (x == "Deny").sum()))
                    .query("n_flows >= 20"))
        ip_stats["deny_ratio"] = ip_stats["n_deny"] / ip_stats["n_flows"] * 100

        most_suspicious_ip  = ip_stats["deny_ratio"].idxmax() if not ip_stats.empty else "N/A"
        sus_ratio           = ip_stats.loc[most_suspicious_ip, "deny_ratio"] if not ip_stats.empty else 0

        # Heure la plus chargée
        peak_hour = int(df_h.groupby("hour").size().idxmax())
        peak_vol  = int(df_h.groupby("hour").size().max())

        # Port le plus ciblé avec Deny
        top_deny_port = (df[df["action"] == "Deny"]
                         .groupby("dst_port").size()
                         .idxmax() if not df[df["action"] == "Deny"].empty else "N/A")

        # IPs externes
        n_ext = len(external_ip_accesses(df))

        c1.metric("IP la + suspecte",   most_suspicious_ip,
                  help="IP avec le plus fort taux Deny (min. 20 flux)")
        c2.metric("Taux Deny de l'IP",  f"{sus_ratio:.0f} %")
        c3.metric("Port le + bloqué",   str(top_deny_port))
        c4.metric("IPs hors réseau",    f"{n_ext:,}")

        st.divider()

        # ── Analyse par heure : pic suspect ? ─────────────────────────────────
        st.subheader("Détection de pic horaire anormal")
        hourly = df_h.groupby(["hour", "action"]).size().reset_index(name="count")
        avg_vol = df_h.groupby("hour").size().mean()
        threshold_line = avg_vol * 1.5

        fig = px.bar(hourly, x="hour", y="count", color="action", barmode="stack",
                     color_discrete_map={"Permit": "#22C55E", "Deny": "#EF4444"},
                     labels={"hour": "Heure", "count": "Flux"})
        fig.add_hline(y=threshold_line, line_dash="dash", line_color="orange",
                      annotation_text=f"Seuil alerte (+50% moy.)", annotation_position="top right")
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0),
                          xaxis=dict(dtick=1, tickvals=list(range(24))))
        st.plotly_chart(fig, use_container_width=True)

        # Heures au-dessus du seuil
        hours_above = df_h.groupby("hour").size()
        hot_hours = hours_above[hours_above > threshold_line].index.tolist()
        if hot_hours:
            st.warning(f"⚠️ Trafic anormalement élevé à : **{', '.join(f'{h}h' for h in hot_hours)}** "
                       f"(>{threshold_line:.0f} flux/h). Possible attaque ou pic de scan.")
        else:
            st.success("✅ Aucun pic horaire anormal détecté — distribution du trafic homogène.")

        st.divider()

        # ── Classement des règles firewall (§1.1) ─────────────────────────────
        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Classement des règles firewall")
            rule_usage = (df.groupby(["policy_id", "action"])
                          .size().reset_index(name="count")
                          .sort_values("count", ascending=False))
            rule_total = (df.groupby("policy_id").size()
                          .reset_index(name="total").sort_values("total", ascending=False))
            fig = px.bar(rule_total.head(15), x="policy_id", y="total",
                         labels={"policy_id": "Règle (policy_id)", "total": "Flux"},
                         color="total", color_continuous_scale="Purples")
            fig.update_layout(xaxis_type="category",
                              plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                              coloraxis_showscale=False, margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)
            top_rule = rule_total.iloc[0]
            st.caption(f"📌 Règle **{top_rule['policy_id']}** est la plus sollicitée "
                       f"({int(top_rule['total']):,} flux). "
                       f"Règle 999 = cleanup (catch-all).")

        with col_b:
            st.subheader("Deny par règle")
            deny_per_rule = (df[df["action"] == "Deny"]
                             .groupby("policy_id").size()
                             .reset_index(name="n_deny")
                             .sort_values("n_deny", ascending=False).head(10))
            fig = px.bar(deny_per_rule, x="policy_id", y="n_deny",
                         labels={"policy_id": "Règle", "n_deny": "Flux Deny"},
                         color_discrete_sequence=["#EF4444"])
            fig.update_layout(xaxis_type="category",
                              plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                              margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)

        st.divider()

        # ── IPs suspectes : Deny ratio élevé ──────────────────────────────────
        st.subheader("IPs suspectes — taux Deny > 30 %")
        suspicious = ip_stats[ip_stats["deny_ratio"] > 30].sort_values("deny_ratio", ascending=False)
        if suspicious.empty:
            st.success("✅ Aucune IP avec un taux Deny > 30%.")
        else:
            fig = px.scatter(suspicious.reset_index(), x="n_flows", y="deny_ratio",
                             size="n_flows", hover_name="src_ip",
                             color="deny_ratio", color_continuous_scale="Reds",
                             labels={"n_flows": "Volume de flux",
                                     "deny_ratio": "% Deny", "src_ip": "IP"},
                             title=f"{len(suspicious)} IP(s) suspectes")
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                              margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# TAB 2 — ISOLATION FOREST
# =============================================================================

with tab_if:
    st.markdown(
        "**Isolation Forest** détecte les flux réseau au comportement atypique "
        "(scans de ports, brute-force, trafic inhabituel)."
    )

    col_p, col_r = st.columns([1, 3])

    with col_p:
        contamination = st.slider(
            "Taux d'anomalie estimé", 0.01, 0.20, 0.05, 0.01,
            help="Proportion attendue de flux anormaux (5% par défaut)")
        n_est = st.slider("Nb d'estimateurs", 50, 300, 100, 50)
        run_btn = st.button("▶ Lancer", type="primary", use_container_width=True)

    with col_r:
        if run_btn or "if_result" not in st.session_state:
            with st.spinner("Entraînement Isolation Forest…"):
                from sklearn.ensemble import IsolationForest

                feats = pd.DataFrame({
                    "dst_port":  df["dst_port"],
                    "hour":      df["timestamp"].dt.hour,
                    "proto_tcp": (df["proto"] == "TCP").astype(int),
                    "is_deny":   (df["action"] == "Deny").astype(int),
                })
                clf    = IsolationForest(n_estimators=n_est,
                                        contamination=contamination, random_state=42)
                clf.fit(feats)
                scores = -clf.score_samples(feats)
                labels = clf.predict(feats)

                df_res = df.copy()
                df_res["anomaly_score"] = scores.round(4)
                df_res["anomaly"]       = labels == -1
                st.session_state["if_result"] = df_res

        df_res = st.session_state["if_result"]
        n_anom = int(df_res["anomaly"].sum())
        ratio  = n_anom / len(df_res) * 100

        ca, cb, cc = st.columns(3)
        ca.metric("Flux analysés",       f"{len(df_res):,}")
        cb.metric("Anomalies détectées", f"{n_anom:,}")
        cc.metric("Score max",           f"{df_res['anomaly_score'].max():.3f}")

        if ratio > 20:
            st.warning(
                f"⚠️ {ratio:.1f}% de flux marqués anomalies — Taux élevé. "
                "Réduire le paramètre 'Taux d'anomalie estimé' ou vérifier les données.")
        else:
            st.info(f"ℹ️ {n_anom:,} flux atypiques ({ratio:.1f}%) identifiés.")

        fig = px.scatter(
            df_res.sample(min(2000, len(df_res)), random_state=42),
            x="dst_port", y="anomaly_score", color="anomaly",
            color_discrete_map={True: "#EF4444", False: "#3B82F6"},
            hover_data=["src_ip", "dst_ip", "proto", "action"],
            labels={"dst_port": "Port", "anomaly_score": "Score d'anomalie",
                    "anomaly": "Anomalie"},
            opacity=0.6, title="Distribution des scores (rouge = suspect)",
        )
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Top 15 flux les plus suspects")
        st.dataframe(
            df_res[df_res["anomaly"]]
            .sort_values("anomaly_score", ascending=False)
            .head(15)[["timestamp", "src_ip", "dst_ip", "dst_port",
                        "proto", "action", "policy_id", "anomaly_score"]],
            use_container_width=True, height=320,
        )


# =============================================================================
# TAB 3 — MISTRAL AI
# =============================================================================

with tab_mistral:
    st.markdown(
        "**Mistral AI** génère un rapport de sécurité en langage naturel "
        "à partir des statistiques du dataset."
    )

    api_key = os.getenv("MISTRAL_API_KEY", "")
    if api_key:
        st.success("✅ Clé API chargée depuis `.env`")
    else:
        st.info("💡 Ajouter `MISTRAL_API_KEY=votre_clé` dans `.env` "
                "ou saisir ci-dessous.", icon="🔑")
        api_key = st.text_input("Clé API Mistral", type="password",
                                placeholder="sk-...", key="mistral_key")

    model_choice = st.selectbox("Modèle",
                                ["mistral-small-latest", "mistral-medium-latest",
                                 "mistral-large-latest"])

    if st.button("🧠 Générer le rapport", type="primary",
                 disabled=not api_key, use_container_width=True):

        deny_p     = compute_deny_ratio(df)
        top5_ips   = top_src_ips(df, 5)["src_ip"].tolist()
        top5_ports = (df.groupby("dst_port").size()
                      .sort_values(ascending=False).head(5).index.tolist())
        n_ext      = len(external_ip_accesses(df))
        proto_cnt  = df.groupby("proto").size().to_dict()
        top_rules  = (df.groupby("policy_id").size()
                      .sort_values(ascending=False).head(3).to_dict())

        prompt = f"""Tu es un expert en cybersécurité réseau. Analyse ces statistiques de logs iptables et rédige un rapport de sécurité concis en français.

DONNÉES ({len(df):,} flux analysés) :
- Taux de Deny : {deny_p}%
- Protocoles : {proto_cnt}
- TOP 5 IPs sources les plus actives : {top5_ips}
- TOP 5 ports les plus ciblés : {top5_ports}
- Flux depuis IPs hors plan d'adressage interne : {n_ext}
- Règles firewall les plus utilisées : {top_rules}
- Période : {df["timestamp"].min().strftime("%d/%m/%Y")} → {df["timestamp"].max().strftime("%d/%m/%Y")}

Structure ta réponse en markdown :
## 1. Résumé de la situation
## 2. Points d'attention
## 3. Recommandations prioritaires"""

        try:
            from mistralai.client import MistralClient
            from mistralai.models.chat_completion import ChatMessage

            with st.spinner("Analyse Mistral en cours…"):
                client   = MistralClient(api_key=api_key)
                response = client.chat(
                    model=model_choice,
                    messages=[ChatMessage(role="user", content=prompt)],
                )
                result = response.choices[0].message.content

            st.success("Rapport généré.")
            st.divider()
            st.markdown(result)
            st.download_button("⬇️ Télécharger le rapport (.md)",
                               data=result.encode("utf-8"),
                               file_name="rapport_securite_mistral.md",
                               mime="text/markdown")

        except Exception as e:
            st.error(f"Erreur Mistral : {e}")
            st.code(str(e))
