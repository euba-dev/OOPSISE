import os
from pathlib import Path

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
from utils.ui import render_sidebar

df = render_sidebar(get_data())

st.header("🤖 IA & ML — Analyse avancée")

tab_agg, tab_kmeans, tab_if2, tab_mistral = st.tabs([
    "📋 Données agrégées",
    "📊 K-Means",
    "🔍 Isolation Forest",
    "💬 Mistral AI",
])

# Agrégation partagée — calculée une seule fois, utilisée par K-Means et IF agrégé
_AGG_FEATURE_COLS = ["nombre_de_connexion", "nb_ip_dst_uniques", "nb_port_dst_uniques"]
df_agg_shared = (
    df.groupby("src_ip")
    .agg(
        nombre_de_connexion=("src_ip", "count"),
        nb_ip_dst_uniques=("dst_ip", "nunique"),
        nb_port_dst_uniques=("dst_port", "nunique"),
    )
    .reset_index()
)


# =============================================================================
# TAB — DONNÉES AGRÉGÉES
# =============================================================================

with tab_agg:
    st.markdown(
        "Tableau des **statistiques comportementales agrégées par IP source**. "
        "Ces données sont utilisées directement par les onglets **K-Means** et **Isolation Forest (agrégé)**."
    )
    st.dataframe(
        df_agg_shared.rename(columns={
            "src_ip":               "IP source",
            "nombre_de_connexion":  "Connexions",
            "nb_ip_dst_uniques":    "IP dst uniques",
            "nb_port_dst_uniques":  "Ports dst uniques",
        }).sort_values("Connexions", ascending=False),
        use_container_width=True,
    )





# =============================================================================
# TAB 2 — MISTRAL AI
# TAB 2 — K-MEANS + ACP
# =============================================================================

with tab_kmeans:
    st.markdown(
        "**K-Means** regroupe automatiquement les **adresses IP sources** en clusters "
        "selon leur comportement réseau : volume de connexions, diversité des IP et ports de destination."
    )
    with st.expander("💡 Comment fonctionne ce clustering ?"):
        st.markdown("""
**Agrégation par IP source**
Pour chaque IP source, on calcule trois métriques comportementales :
- **nombre_de_connexion** : combien de fois cette IP a-t-elle généré une connexion ?
- **nb_ip_dst_uniques** : combien d'IP de destination différentes a-t-elle contactées ?
- **nb_port_dst_uniques** : combien de ports de destination différents a-t-elle ciblés ?

Une IP qui tente de nombreux ports ou IP différents est suspecte (scan réseau).

**Pipeline :**
1. Agrégation → une ligne par IP source
2. StandardScaler → centrage-réduction (moyenne = 0, écart-type = 1)
3. KMeans → méthode du coude pour choisir k automatiquement
4. Visualisation → t-SNE 3D interactif avec axes annotés
""")

    col_p, col_r = st.columns([1, 3])

    with col_p:
        k_max = st.slider(
            "K maximum à tester",
            3, 15, 10,
            help="L'algorithme testera toutes les valeurs de k de 2 jusqu'à ce maximum pour trouver le coude.",
            key="km_kmax",
        )
        run_km = st.button("▶ Lancer K-Means", type="primary", use_container_width=True, key="run_km")

    with col_r:
        if run_km or "km_result" not in st.session_state:
            with st.spinner("Clustering K-Means en cours…"):
                from sklearn.cluster import KMeans
                from sklearn.manifold import TSNE
                from sklearn.preprocessing import StandardScaler

                # — Agrégation partagée (calculée une fois en dehors des tabs) —
                df_agg = df_agg_shared.copy()

                # — Centrage-réduction —
                feature_cols = _AGG_FEATURE_COLS
                X = StandardScaler().fit_transform(df_agg[feature_cols].values)

                # — Méthode du coude —
                # Plafonner k_max au nombre d'IPs disponibles (évite n_samples < n_clusters)
                k_max = min(k_max, len(df_agg) - 1)
                if k_max < 2:
                    st.warning("Pas assez d'IPs sources pour former des clusters (minimum 3 requis).")
                    st.stop()
                ks = list(range(2, k_max + 1))
                inertias = []
                for k in ks:
                    km = KMeans(n_clusters=k, random_state=42, n_init=10)
                    km.fit(X)
                    inertias.append(km.inertia_)

                if len(inertias) >= 3:
                    d1 = [inertias[i] - inertias[i + 1] for i in range(len(inertias) - 1)]
                    d2 = [d1[i] - d1[i + 1] for i in range(len(d1) - 1)]
                    k_opt = ks[d2.index(max(d2)) + 1]
                else:
                    k_opt = ks[0]

                # — Clustering final —
                km_final = KMeans(n_clusters=k_opt, random_state=42, n_init=10)
                df_agg["Cluster"] = [f"Cluster {l}" for l in km_final.fit_predict(X)]

                # — t-SNE 3D —
                # t-SNE 3D requiert au moins 4 points ; on replie sur 2D si trop peu de données
                n_components_tsne = 3 if len(df_agg) > 3 else 2
                perp = min(30, len(df_agg) - 1)
                tsne_coords = TSNE(
                    n_components=n_components_tsne, random_state=42, perplexity=perp, max_iter=1000,
                ).fit_transform(X)
                df_agg["tsne_x"] = tsne_coords[:, 0]
                df_agg["tsne_y"] = tsne_coords[:, 1]
                df_agg["tsne_z"] = tsne_coords[:, 2] if n_components_tsne == 3 else 0.0

                # Nommer les axes par corrélation — affectation gloutonne (sans doublons)
                axis_labels = []
                used_features = set()
                for ax_col in ["tsne_x", "tsne_y", "tsne_z"]:
                    corrs = df_agg[feature_cols + [ax_col]].corr()[ax_col][feature_cols].abs()
                    available = corrs.drop(index=list(used_features))
                    if available.empty:
                        available = corrs  # fallback si toutes les features sont déjà utilisées
                    best = available.idxmax()
                    r = available.max()
                    used_features.add(best)
                    axis_labels.append(f"{best} (r = {r:.2f})")

                st.session_state["km_result"] = {
                    "df_agg":       df_agg,
                    "ks":           ks,
                    "inertias":     inertias,
                    "k_opt":        k_opt,
                    "axis_labels":  axis_labels,
                    "feature_cols": feature_cols,
                }

        res          = st.session_state["km_result"]
        df_agg       = res["df_agg"]
        k_opt        = res["k_opt"]
        axis_labels  = res["axis_labels"]
        feature_cols = res["feature_cols"]

        st.info(f"🎯 Coude détecté automatiquement : **k = {k_opt}** clusters.")

        # — Tableau agrégé + cluster (données brutes disponibles dans l'onglet "Données agrégées") —
        st.subheader("Données agrégées — résultat du clustering")
        st.dataframe(
            df_agg[["src_ip", "nombre_de_connexion", "nb_ip_dst_uniques", "nb_port_dst_uniques", "Cluster"]]
            .rename(columns={
                "src_ip":               "IP source",
                "nombre_de_connexion":  "Connexions",
                "nb_ip_dst_uniques":    "IP dst uniques",
                "nb_port_dst_uniques":  "Ports dst uniques",
            })
            .sort_values("Connexions", ascending=False),
            use_container_width=True,
            height=300,
        )

        # — Graphique du coude —
        with st.expander("💡 Comment lire le graphique du coude ?"):
            st.markdown("""
- L'**axe horizontal** = nombre de clusters testés.
- L'**axe vertical** = inertie : dispersion interne des groupes. Plus c'est bas, mieux les groupes sont définis.
- La **ligne pointillée rouge** marque le coude détecté automatiquement — meilleur compromis entre précision et simplicité.
""")
        fig_elbow = px.line(
            x=res["ks"], y=res["inertias"],
            markers=True,
            labels={"x": "Nombre de clusters (k)", "y": "Inertie"},
            title="Méthode du coude — choix automatique de k",
        )
        fig_elbow.add_vline(
            x=k_opt, line_dash="dash", line_color="#EF4444",
            annotation_text=f"k optimal = {k_opt}",
            annotation_font_color="#EF4444",
        )
        fig_elbow.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=40, b=0),
        )
        st.plotly_chart(fig_elbow, use_container_width=True)

        # — t-SNE 3D annoté —
        st.subheader("Projection t-SNE 3D — séparation globale des clusters")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
**t-SNE** projette les IPs dans un espace 3D en préservant les similarités locales.
- Chaque **point** = une IP source.
- Chaque **couleur** = un cluster.
- Les **axes sont annotés** avec la variable originale la plus corrélée à chaque direction.
- Des groupes bien séparés = clusters cohérents et distincts.
- Utilisez la souris pour **faire tourner** le graphique et explorer les clusters sous différents angles.
""")
        ax1, ax2, ax3 = axis_labels
        fig_tsne = px.scatter_3d(
            df_agg,
            x="tsne_x", y="tsne_y", z="tsne_z",
            color="Cluster",
            hover_data=["src_ip", "nombre_de_connexion", "nb_ip_dst_uniques", "nb_port_dst_uniques"],
            labels={"tsne_x": ax1, "tsne_y": ax2, "tsne_z": ax3},
            opacity=0.8,
            title=f"t-SNE 3D — {k_opt} clusters d'IPs sources",
            color_discrete_sequence=px.colors.qualitative.Set1,
        )
        fig_tsne.update_traces(marker=dict(size=5))
        fig_tsne.update_layout(
            margin=dict(l=0, r=0, b=0, t=40),
            scene=dict(
                xaxis=dict(title=ax1),
                yaxis=dict(title=ax2),
                zaxis=dict(title=ax3),
            ),
            scene_camera=dict(eye=dict(x=1.2, y=1.2, z=0.6)),
        )
        st.plotly_chart(fig_tsne, use_container_width=True)

        # — Profil des clusters —
        st.subheader("Profil des clusters")
        with st.expander("💡 Comment lire ce tableau ?"):
            st.markdown("""
- **Nb_IPs** : nombre d'adresses IP dans ce cluster.
- **Connexions_moy** : nombre moyen de connexions par IP.
- **IP_dst_moy** : nombre moyen d'IP de destination distinctes contactées.
- **Ports_dst_moy** : nombre moyen de ports de destination distincts ciblés — élevé = potentiel scan réseau.
""")
        profile = (
            df_agg.groupby("Cluster")
            .agg(
                Nb_IPs=("src_ip", "count"),
                Connexions_moy=("nombre_de_connexion", "mean"),
                IP_dst_moy=("nb_ip_dst_uniques", "mean"),
                Ports_dst_moy=("nb_port_dst_uniques", "mean"),
            )
            .round(1)
        )
        st.dataframe(profile, use_container_width=True)


# =============================================================================
# TAB 3 — ISOLATION FOREST (AGRÉGÉ)
# =============================================================================

with tab_if2:
    st.markdown(
        "**Isolation Forest** applique la détection d'anomalies "
        " sur le **profil comportemental de chaque IP source** (connexions totales, IP et ports ciblés)."
    )
    with st.expander("💡 Comment fonctionne cet Isolation Forest ?"):
        st.markdown("""
**Pourquoi agréger avant de détecter ?**
Détecter une anomalie connexion par connexion peut rater les IPs qui semblent normales sur chaque flux
mais ont un comportement global suspect (ex. : 1 000 connexions vers 500 ports différents).

**Pipeline :**
1. Agrégation → une ligne par IP (`nombre_de_connexion`, `nb_ip_dst_uniques`, `nb_port_dst_uniques`)
2. StandardScaler → centrage-réduction
3. IsolationForest → score d'anomalie par IP
4. Les IPs avec un score élevé sont signalées comme **suspectes**
""")

    col_p2, col_r2 = st.columns([1, 3])

    with col_p2:
        contamination2 = st.slider(
            "Proportion d'anomalies attendue",
            0.01, 0.3, 0.05, step=0.01,
            help="Part des IPs considérées comme anormales. 5 % = 1 IP sur 20.",
            key="if2_contamination",
        )
        run_if2 = st.button("▶ Lancer Isolation Forest", type="primary",
                            use_container_width=True, key="run_if2")

    with col_r2:
        if run_if2 or "if2_result" not in st.session_state:
            with st.spinner("Isolation Forest agrégé en cours…"):
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler

                # — Agrégation partagée (calculée une fois en dehors des tabs) —
                df_agg2 = df_agg_shared.copy()

                X2 = StandardScaler().fit_transform(df_agg2[_AGG_FEATURE_COLS].values)

                clf = IsolationForest(contamination=contamination2, random_state=42)
                df_agg2["anomaly"] = clf.fit_predict(X2)          # -1 = anomalie, 1 = normal
                df_agg2["score"]   = -clf.score_samples(X2)       # plus élevé = plus suspect
                df_agg2["Statut"]  = df_agg2["anomaly"].map({1: "Normal", -1: "Suspect"})

                st.session_state["if2_result"] = {"df_agg2": df_agg2}

        df_agg2  = st.session_state["if2_result"]["df_agg2"]
        n_sus    = (df_agg2["Statut"] == "Suspect").sum()
        n_total  = len(df_agg2)

        st.info(f"**{n_sus} IPs suspectes** détectées sur {n_total} IPs sources analysées.")

        # — Tableau agrégé + scores (données brutes disponibles dans l'onglet "Données agrégées") —
        st.subheader("Données agrégées — scores d'anomalie")
        st.dataframe(
            df_agg2[["src_ip", "nombre_de_connexion", "nb_ip_dst_uniques",
                     "nb_port_dst_uniques", "score", "Statut"]]
            .rename(columns={
                "src_ip":               "IP source",
                "nombre_de_connexion":  "Connexions",
                "nb_ip_dst_uniques":    "IP dst uniques",
                "nb_port_dst_uniques":  "Ports dst uniques",
                "score":                "Score anomalie",
            })
            .sort_values("Score anomalie", ascending=False),
            use_container_width=True,
            height=300,
        )

        # — Scatter : IP dst vs ports dst, coloré par score d'anomalie —
        st.subheader("Visualisation des anomalies — IP destinations vs ports ciblés")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
- Chaque **point** = une IP source.
- L'**axe X** = nombre d'IP de destination distinctes contactées.
- L'**axe Y** = nombre de ports de destination distincts ciblés.
- La **couleur** représente le score d'anomalie : plus c'est foncé/chaud, plus l'IP est suspecte.
- Une IP en haut à droite (beaucoup d'IP **et** beaucoup de ports) est un signal fort de scan réseau.
- Survolez un point pour voir l'adresse IP et son score exact.
""")
        fig_if2 = px.scatter(
            df_agg2,
            x="nb_ip_dst_uniques",
            y="nb_port_dst_uniques",
            color="score",
            hover_data=["src_ip", "nombre_de_connexion", "Statut"],
            labels={
                "nb_ip_dst_uniques":   "IP destinations uniques",
                "nb_port_dst_uniques": "Ports destinations uniques",
                "score":               "Score anomalie",
            },
            color_continuous_scale="Reds",
            opacity=0.85,
            title="Isolation Forest agrégé — score d'anomalie par IP source",
        )
        fig_if2.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=40, b=0),
        )
        st.plotly_chart(fig_if2, use_container_width=True)

        # — Top IPs suspectes —
        st.subheader("Top IPs suspectes")
        suspects = (
            df_agg2[df_agg2["Statut"] == "Suspect"]
            .sort_values("score", ascending=False)
            [["src_ip", "nombre_de_connexion", "nb_ip_dst_uniques", "nb_port_dst_uniques", "score"]]
            .rename(columns={
                "src_ip":               "IP source",
                "nombre_de_connexion":  "Connexions",
                "nb_ip_dst_uniques":    "IP dst uniques",
                "nb_port_dst_uniques":  "Ports dst uniques",
                "score":                "Score anomalie",
            })
            .round({"Score anomalie": 4})
        )
        st.dataframe(suspects, use_container_width=True)


# =============================================================================
# TAB 4 — MISTRAL AI
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
