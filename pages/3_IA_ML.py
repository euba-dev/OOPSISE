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

tab_if, tab_mistral = st.tabs([
    "🔍 Isolation Forest",
    "💬 Mistral AI",
])


# =============================================================================
# TAB 1 — ISOLATION FOREST
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
# TAB 2 — MISTRAL AI
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
