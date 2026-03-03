import os

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from utils.data_loader import get_data
from utils.helpers import (
    add_port_category,
    compute_daily_traffic,
    compute_deny_ratio,
    external_ip_accesses,
    ip_traffic_summary,
    port_category_distribution,
    port_label,
    top_permitted_ports_under_1024,
    top_src_ips,
)
from utils.ui import render_sidebar

_src = st.session_state.get("_data_source", "mock")
df = render_sidebar(get_data(_src))

st.header("📊 Dashboard")

# ── Priorités métier ────────────────────────────────────────────────────────
st.subheader("🧠 Priorités métier")

_api_key = os.getenv("MISTRAL_API_KEY", "")
if not _api_key:
    st.info(
        "Configurer `MISTRAL_API_KEY` dans `.env` pour activer l'analyse.",
        icon="🔑",
    )
else:
    # Empreinte des filtres courants pour détecter si l'analyse est périmée
    _cur_hash = (
        f"{len(df)}|{compute_deny_ratio(df)}"
        f"|{df['timestamp'].min().date()}|{df['timestamp'].max().date()}"
    )
    _stale = (
        "priorities_result" in st.session_state
        and st.session_state.get("priorities_hash", "") != _cur_hash
    )

    with st.container(border=True):
        _col_desc, _col_btn = st.columns([5, 1])
        _has_result  = "priorities_result" in st.session_state
        _up_to_date  = _has_result and not _stale
        with _col_desc:
            if _stale:
                st.markdown("⚠️ _Les filtres ont changé — cliquez sur **Actualiser** pour relancer l'analyse._")
            elif _up_to_date:
                st.markdown("✅ _Analyse à jour avec les données filtrées ci-dessous._")
            else:
                st.markdown("_Mistral identifie les priorités métier sur les données filtrées ci-dessous._")
        with _col_btn:
            run_prio = st.button(
                "🔄 Actualiser" if _stale else "🧠 Analyser",
                type="secondary",
                disabled=_up_to_date,
                use_container_width=True,
            )

        if run_prio or "priorities_result" in st.session_state:
            if run_prio:
                _deny_p   = compute_deny_ratio(df)
                _top3_ips = top_src_ips(df, 3)["src_ip"].tolist()
                _top3_pts = (
                    df.groupby("dst_port").size()
                    .sort_values(ascending=False).head(3).index.tolist()
                )
                _n_ext    = len(external_ip_accesses(df))
                _h_totals = df.groupby(df["timestamp"].dt.hour).size()
                _peak_h   = int(_h_totals.idxmax()) if not _h_totals.empty else 0
                _top_rule = (
                    df.groupby("policy_id").size()
                    .sort_values(ascending=False).index[0]
                    if not df.empty else "—"
                )
                _d_min = df["timestamp"].min().strftime("%d/%m/%Y") if not df.empty else "—"
                _d_max = df["timestamp"].max().strftime("%d/%m/%Y") if not df.empty else "—"

                _prompt = f"""Tu es un analyste SOC expérimenté. Voici les statistiques de logs firewall filtrés.

PÉRIODE : {_d_min} → {_d_max} | {len(df):,} flux analysés
MÉTRIQUES :
- Taux de Deny : {_deny_p}%
- Top 3 IPs sources actives : {_top3_ips}
- Top 3 ports les plus ciblés : {[port_label(p) for p in _top3_pts]}
- Flux depuis IPs externes : {_n_ext:,}
- Heure de pic de trafic : {_peak_h}h
- Règle firewall la plus sollicitée : {_top_rule}

CONSIGNE STRICTE — réponds UNIQUEMENT avec 3 à 5 lignes. Chaque ligne DOIT se terminer par la référence entre parenthèses.
Voici des exemples de vrai output attendu — remplace le contenu par les données réelles ci-dessus :
🔴 **[Critique]** Taux de Deny critique — plus d'un quart des connexions sont bloquées (voir onglet Vue générale > Taux de blocage)
🟡 **[Attention]** Port 22 très sollicité — possible brute force SSH en cours (voir onglet Ports & Protocoles > TOP 15 ports)
🟢 **[Info]** Pic de trafic à 6h — vérifier les tâches automatisées nocturnes (voir onglet Vue générale > Trafic horaire)
Onglets et graphiques disponibles :
- Vue générale : Trafic horaire, Carte thermique, Taux de blocage, TOP 5 IPs, TOP 10 ports Permit, IPs externes, Règles firewall
- Ports & Protocoles : Flux par protocole, Catégories RFC 6056, TOP 15 ports, Catégorie × Décision
- IP Explorer : Scatter interactif

Aucune introduction. Aucune conclusion. Seulement les priorités."""

                try:
                    from mistralai import Mistral

                    with st.spinner("Mistral analyse les priorités…"):
                        client = Mistral(api_key=_api_key)
                        resp = client.chat.complete(
                            model="mistral-small-latest",
                            messages=[{"role": "user", "content": _prompt}],
                        )
                        st.session_state["priorities_result"] = resp.choices[0].message.content
                        st.session_state["priorities_hash"]   = _cur_hash
                except Exception as e:
                    st.error(f"Erreur Mistral : {e}")

        if "priorities_result" in st.session_state:
            if _stale and not run_prio:
                st.caption("_Résultat de la dernière analyse — filtres modifiés depuis_")
            _prio_lines = [l for l in st.session_state["priorities_result"].split("\n") if l.strip()]
            st.markdown("\n\n".join(_prio_lines))
            st.caption("_Généré par Mistral AI · mistral-small-latest_")

st.divider()

t1, t2, t3 = st.tabs(["Vue générale", "🔌 Ports & Protocoles", "🌐 IP Explorer"])

# =============================================================================
# TAB 1 — VUE GÉNÉRALE
# =============================================================================

with t1:
    deny_pct = compute_deny_ratio(df)
    n_ext    = len(external_ip_accesses(df))

    # Métriques principales
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total flux",            f"{len(df):,}",
              help="Nombre total de connexions enregistrées par le pare-feu sur la période.")
    c2.metric("Taux de Deny",          f"{deny_pct} %",
              help="Part des connexions bloquées par le pare-feu. Un taux élevé peut signaler une activité malveillante.")
    c3.metric("IP sources uniques",    f"{df['src_ip'].nunique():,}",
              help="Nombre de machines distinctes ayant généré du trafic.")
    c4.metric("Règles actives",        f"{df['policy_id'].nunique()}",
              help="Nombre de règles du pare-feu ayant été déclenchées sur la période.")
    c5.metric("IPs hors réseau interne", f"{n_ext:,}",
              help="Flux provenant d'adresses IP extérieures au réseau de l'université.")

    # Interprétation du taux de Deny
    if deny_pct >= 25:
        st.error(
            f"🚨 **Taux de Deny critique ({deny_pct}%)** — Plus d'un quart des connexions sont bloquées. "
            "Cela peut indiquer un scan massif, une attaque par force brute ou un DDoS. "
            "Il est recommandé d'examiner immédiatement les IP sources les plus actives."
        )
    elif deny_pct >= 15:
        st.warning(
            f"⚠️ **Taux de Deny élevé ({deny_pct}%)** — En pratique, un taux supérieur à ~15% est souvent "
            "considéré comme un signal d'alerte à investiguer (ce seuil est indicatif, pas une norme officielle). "
            "Surveiller les IP sources et les ports les plus ciblés."
        )
    else:
        st.success(
            f"✅ **Taux de Deny normal ({deny_pct}%)** — Le trafic bloqué reste dans une proportion habituelle. "
            "Aucune anomalie globale détectée."
        )

    st.divider()

    # ── Trafic horaire ─────────────────────────────────────────────────────────
    col_l, col_r = st.columns([2, 1])

    with col_l:
        st.subheader("Trafic par heure de la journée")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
- Chaque barre représente une **heure de la journée** (0h à 23h).
- La **partie verte** = connexions autorisées (*Permit*), la **partie rouge** = connexions bloquées (*Deny*).
- La **ligne orange pointillée** est un seuil d'alerte automatique : si une heure dépasse 1,5× la moyenne horaire,
  cela peut indiquer un pic de trafic inhabituel (ex. tentative d'intrusion, scan de réseau).
""")
        df_h = df.copy()
        df_h["hour"] = df_h["timestamp"].dt.hour
        hourly_action = df_h.groupby(["hour", "action"]).size().reset_index(name="count")
        hourly_total  = df_h.groupby("hour").size()
        avg_vol        = hourly_total.mean()
        threshold_line = avg_vol * 1.5
        peak_h         = int(hourly_total.idxmax())
        peak_cnt       = int(hourly_total.max())

        fig = px.bar(hourly_action, x="hour", y="count", color="action", barmode="stack",
                     color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                     labels={"hour": "Heure (UTC)", "count": "Nombre de connexions", "action": "Décision"})
        fig.add_hline(y=threshold_line, line_dash="dash", line_color="orange",
                      annotation_text="Seuil alerte (+50% moy.)",
                      annotation_position="top right")
        fig.update_layout(xaxis=dict(dtick=1, tickvals=list(range(24))),
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

        hot_hours = hourly_total[hourly_total > threshold_line].index.tolist()
        if hot_hours:
            st.warning(
                f"⚠️ Trafic anormalement élevé à : **{', '.join(f'{h}h' for h in hot_hours)}** "
                f"(>{threshold_line:.0f} connexions/h). Possible attaque ou pic de scan."
            )
        else:
            st.markdown(f"📌 Pic de trafic à **{peak_h}h** avec **{peak_cnt:,}** connexions — "
                        "distribution homogène sur la journée.")

    with col_r:
        st.subheader("Taux de blocage")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
La **jauge** indique le pourcentage de connexions bloquées sur la période.
- 🟢 Zone verte (0–15 %) : taux normal
- 🟡 Zone jaune (15–25 %) : signal d'alerte à surveiller
- 🔴 Zone rouge (25–50 %) : taux critique — investigation immédiate
""")
        _gc = "#F87171" if deny_pct >= 25 else "#FBBF24" if deny_pct >= 15 else "#4ADE80"
        fig_g = go.Figure(go.Indicator(
            mode="gauge+number",
            value=deny_pct,
            number={"suffix": "%", "font": {"size": 32}},
            title={"text": "Deny", "font": {"size": 13}},
            gauge={
                "axis": {"range": [0, 50], "tickwidth": 1},
                "bar": {"color": _gc, "thickness": 0.6},
                "bgcolor": "rgba(0,0,0,0)",
                "steps": [
                    {"range": [0, 15],  "color": "rgba(74,222,128,0.12)"},
                    {"range": [15, 25], "color": "rgba(251,191,36,0.12)"},
                    {"range": [25, 50], "color": "rgba(248,113,113,0.12)"},
                ],
                "threshold": {
                    "line": {"color": "#FBBF24", "width": 2},
                    "thickness": 0.75,
                    "value": 15,
                },
            },
        ))
        fig_g.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=10, r=10, t=30, b=10),
            height=230,
        )
        st.plotly_chart(fig_g, use_container_width=True)

    st.divider()

    # ── Carte thermique heure × jour ────────────────────────────────────────────
    n_days_data = (df["timestamp"].max() - df["timestamp"].min()).days
    if n_days_data >= 1:
        st.subheader("Carte thermique du trafic — heure × jour")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
- Chaque **cellule** représente le volume total de connexions pour une heure précise d'un jour de la semaine.
- Plus la cellule est **foncée**, plus le trafic est intense à ce créneau.
- Chercher des **patterns anormaux** : activité nocturne intense, pic le week-end, heure inhabituelle.
- Ce graphique cumule toutes les occurrences de ce jour/heure sur la période analysée.
""")
        _DAYS_FR = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
        _hm = df.copy()
        _hm["hour"] = _hm["timestamp"].dt.hour
        _hm["day"]  = _hm["timestamp"].dt.dayofweek.map(dict(enumerate(_DAYS_FR)))
        _pivot = (
            _hm.groupby(["day", "hour"]).size()
            .reset_index(name="count")
            .pivot(index="day", columns="hour", values="count")
            .fillna(0)
            .reindex(index=[d for d in _DAYS_FR if d in _hm["day"].unique()])
            .reindex(columns=range(24), fill_value=0)
        )
        import numpy as _np
        fig_hm = px.imshow(
            _np.log1p(_pivot),
            color_continuous_scale="Blues",
            labels={"x": "Heure", "y": "Jour", "color": "log(Connexions+1)"},
            aspect="auto",
        )
        fig_hm.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0),
        )
        st.plotly_chart(fig_hm, use_container_width=True)
        _peak_cell = _hm.groupby(["day", "hour"]).size().idxmax()
        st.markdown(
            f"📌 Pic d'activité : **{_peak_cell[0]}** à **{_peak_cell[1]}h** "
            "— créneau le plus chargé sur la période."
        )
        st.divider()

    # ── TOP 5 IPs + TOP 10 ports < 1024 Permit ────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("TOP 5 IP sources les plus émettrices")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Chaque barre représente une **adresse IP source** et le nombre total de connexions qu'elle a générées
(Permit + Deny confondus). Une IP très active mérite attention : elle peut être légitime (serveur applicatif)
ou suspecte (scanner de réseau, machine compromise).
""")
        top5 = top_src_ips(df, n=5)
        fig = px.bar(top5, x="count", y="src_ip", orientation="h",
                     labels={"src_ip": "IP source", "count": "Nombre de connexions"},
                     color_discrete_sequence=["#60A5FA"])
        fig.update_layout(yaxis=dict(autorange="reversed"),
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        t1ip = top5.iloc[0]
        st.markdown(f"📌 **{t1ip['src_ip']}** est la machine la plus active — **{t1ip['count']:,}** connexions émises.")

    with col_b:
        st.subheader("TOP 10 ports < 1024 autorisés (Permit)")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Les **ports inférieurs à 1024** sont appelés "well-known ports" : chacun correspond à un service
réseau standardisé (80 = HTTP, 443 = HTTPS, 22 = SSH, 21 = FTP…). Ce graphique montre
lesquels sont les plus sollicités parmi les connexions **autorisées**. Cela indique quels
services sont réellement utilisés sur le réseau.
""")
        tp = top_permitted_ports_under_1024(df, n=10)
        if tp.empty:
            st.info("Aucun flux Permit sur ports < 1024 avec les filtres actuels.")
        else:
            tp["port_lbl"] = tp["dst_port"].apply(port_label)
            fig = px.bar(tp, x="port_lbl", y="count",
                         labels={"port_lbl": "Port", "count": "Connexions autorisées"},
                         color_discrete_sequence=["#4ADE80"])
            fig.update_layout(xaxis_type="category",
                              plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                              margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)
            st.markdown(f"📌 **{port_label(int(tp.iloc[0]['dst_port']))}** — "
                        f"**{int(tp.iloc[0]['count']):,}** connexions autorisées, service le plus sollicité.")

    # ── IPs hors plan interne ──────────────────────────────────────────────────
    ext_df = external_ip_accesses(df)
    if not ext_df.empty:
        st.subheader(f"Accès depuis IPs hors réseau interne — {len(ext_df):,} flux")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Ce graphique recense les connexions provenant d'**adresses IP externes** (internet), c'est-à-dire
hors du réseau de l'université. Chaque barre représente une IP externe et le nombre de connexions
qu'elle a tenté d'établir, ventilé entre autorisées (🟢) et bloquées (🔴).

Une IP externe générant beaucoup de *Deny* peut être un scanner automatique ou une tentative d'intrusion.
Une IP externe avec des *Permit* signifie qu'elle a réussi à établir des connexions — à vérifier
qu'elles correspondent à des services intentionnellement ouverts vers internet.
""")
        ext_agg = (ext_df.groupby(["src_ip", "action"], as_index=False)
                   .size().rename(columns={"size": "count"})
                   .sort_values("count", ascending=False).head(20))
        fig = px.bar(ext_agg, x="src_ip", y="count", color="action",
                     color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                     labels={"src_ip": "IP source (externe)", "count": "Connexions", "action": "Décision"})
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        n_permit_ext = len(ext_df[ext_df["action"] == "Permit"])
        if n_permit_ext > 0:
            st.warning(f"⚠️ {n_permit_ext:,} connexions **autorisées** depuis des IPs extérieures au réseau interne — "
                       "Vérifier qu'elles correspondent à des services intentionnellement accessibles depuis internet.")

    st.divider()

    # ── Classement des règles firewall ─────────────────────────────────────────
    col_r1, col_r2 = st.columns(2)

    with col_r1:
        st.subheader("Règles firewall les plus déclenchées")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Le pare-feu possède une liste numérotée de **règles** (aussi appelées *policies*). Quand un flux
réseau arrive, le pare-feu parcourt ces règles dans l'ordre et applique la première qui correspond.

Ce graphique montre combien de fois chaque règle a été déclenchée. Une règle très sollicitée
traite beaucoup de trafic — ce n'est pas forcément suspect, cela dépend de ce que fait la règle.

**Règle 999** : c'est la règle "catch-all" (ou *cleanup*). Elle est placée en dernier et bloque
automatiquement tout trafic qui n'a pas correspondu à une règle précédente. Si elle est très
sollicitée, cela signifie qu'il y a beaucoup de trafic non prévu dans la configuration du pare-feu.
""")
        rule_total = (df.groupby("policy_id").size()
                      .reset_index(name="total").sort_values("total", ascending=False))
        fig = px.bar(rule_total.head(15), x="policy_id", y="total",
                     labels={"policy_id": "Numéro de règle", "total": "Nombre de déclenchements"},
                     color_discrete_sequence=["#A78BFA"])
        fig.update_layout(xaxis_type="category",
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        top_rule = rule_total.iloc[0]
        is_cleanup = top_rule['policy_id'] == "999"
        st.markdown(
            f"📌 Règle **{top_rule['policy_id']}** déclenchée **{int(top_rule['total']):,}** fois — "
            + ("règle *catch-all* : bloque tout trafic non explicitement autorisé." if is_cleanup
               else "règle la plus sollicitée sur la période.")
        )

    with col_r2:
        st.subheader("Règles avec le plus de connexions bloquées")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Ce graphique se concentre uniquement sur les connexions **bloquées** (*Deny*), et montre
quelles règles du pare-feu sont responsables de ces blocages. Une règle qui bloque beaucoup
peut indiquer qu'un certain type de trafic est fréquemment tenté mais interdit.
""")
        deny_per_rule = (df[df["action"] == "Deny"]
                         .groupby("policy_id").size()
                         .reset_index(name="n_deny")
                         .sort_values("n_deny", ascending=False).head(10))
        fig = px.bar(deny_per_rule, x="policy_id", y="n_deny",
                     labels={"policy_id": "Numéro de règle", "n_deny": "Connexions bloquées"},
                     color_discrete_sequence=["#F87171"])
        fig.update_layout(xaxis_type="category",
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# TAB 2 — PORTS & PROTOCOLES
# =============================================================================

with t2:
    df_p   = add_port_category(df)
    _COLORS = {"Well-known": "#818CF8", "Registered": "#FBBF24", "Dynamic/Private": "#34D399"}

    st.subheader("Flux par protocole et décision du pare-feu")
    with st.expander("💡 Comment lire ce graphique ?"):
        st.markdown("""
- **TCP** (*Transmission Control Protocol*) : protocole fiable, utilisé pour le web, SSH, email…
  Il garantit que les données arrivent correctement.
- **UDP** (*User Datagram Protocol*) : protocole rapide mais sans garantie, utilisé pour le DNS,
  la vidéo en streaming, les jeux en ligne…

Ce graphique montre pour chaque protocole combien de connexions ont été autorisées (🟢) ou bloquées (🔴).
Un taux de Deny élevé sur UDP peut indiquer des scans réseau ou du trafic DNS non sollicité.
""")
    proto_cross = (df.groupby(["proto", "action"], as_index=False)
                   .size().rename(columns={"size": "count"}))
    _pt = proto_cross.groupby("proto")["count"].transform("sum")
    proto_cross["pct"]   = (proto_cross["count"] / _pt * 100).round(1)
    proto_cross["label"] = proto_cross["pct"].apply(lambda x: f"{x:.0f}%")
    fig = px.bar(proto_cross, x="proto", y="count", color="action", barmode="group",
                 text="label",
                 color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                 labels={"proto": "Protocole", "count": "Connexions", "action": "Décision"})
    fig.update_traces(
        textfont_size=11, textposition="outside",
        hovertemplate="<b>%{x}</b> · %{data.name}<br>Connexions : <b>%{y:,}</b><br>Part du protocole : <b>%{text}</b><extra></extra>",
    )
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=0, r=0, t=30, b=0), uniformtext_minsize=8)
    st.plotly_chart(fig, use_container_width=True)
    top_proto     = df.groupby("proto")["proto"].count().idxmax()
    deny_by_proto = df[df["action"] == "Deny"].groupby("proto").size()
    st.markdown(
        f"📌 **{top_proto}** est le protocole dominant — "
        f"Deny TCP : **{deny_by_proto.get('TCP', 0):,}** · "
        f"Deny UDP : **{deny_by_proto.get('UDP', 0):,}**."
    )

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Catégories de ports (RFC 6056)")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Les ports réseau sont divisés en 3 grandes catégories selon la norme RFC 6056 :
- 🟣 **Well-known (0–1023)** : ports réservés aux services standards (HTTP, SSH, DNS…)
- 🟡 **Registered (1024–49151)** : ports pour des applications connues (MySQL, Redis…)
- 🟢 **Dynamic/Private (49152–65535)** : ports temporaires, utilisés par les connexions sortantes

Un trafic massif vers des ports *Dynamic/Private* peut indiquer des communications
non standard ou des scans aléatoires.
""")
        dist = port_category_distribution(df_p)
        fig = px.pie(dist, names="port_category", values="count",
                     color="port_category", color_discrete_map=_COLORS, hole=0.4)
        fig.update_layout(margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        st.markdown(
            f"📌 Les ports **{dist.iloc[0]['port_category']}** représentent la majorité du trafic "
            f"— **{int(dist.iloc[0]['count']):,}** connexions."
        )
        with st.expander("Récapitulatif des plages de ports"):
            st.markdown(
                "| Plage | Catégorie | Exemples de services |\n|---|---|---|\n"
                "| 0 – 1023 | **Well-known** | HTTP (80), HTTPS (443), SSH (22), DNS (53), FTP (21) |\n"
                "| 1024 – 49151 | **Registered** | MySQL (3306), Redis (6379), RDP (3389) |\n"
                "| 49152 – 65535 | **Dynamic/Private** | Ports éphémères (connexions sortantes) |"
            )

    with col_b:
        st.subheader("TOP 15 ports les plus ciblés")
        with st.expander("💡 Comment lire ce graphique ?"):
            st.markdown("""
Ce graphique montre les 15 ports qui reçoivent le plus de connexions, avec la répartition **Permit / Deny**.
- 🟢 La partie verte = connexions **autorisées**
- 🔴 La partie rouge = connexions **bloquées**

Un port avec beaucoup de rouge peut être la cible d'un scan automatisé
(ex. le port 22/SSH est souvent scanné par des robots en force brute).
""")
        _top15_ids = (
            df_p.groupby("dst_port").size()
            .sort_values(ascending=False).head(15).index.tolist()
        )
        top_ports = (
            df_p[df_p["dst_port"].isin(_top15_ids)]
            .groupby(["dst_port", "action"], as_index=False)
            .size().rename(columns={"size": "count"})
        )
        top_ports["port_lbl"] = top_ports["dst_port"].apply(port_label)
        _port_order = (
            top_ports.groupby("port_lbl")["count"].sum()
            .sort_values(ascending=False).index.tolist()
        )
        fig = px.bar(top_ports, x="port_lbl", y="count", color="action", barmode="stack",
                     category_orders={"port_lbl": _port_order},
                     color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                     labels={"port_lbl": "Port", "count": "Connexions", "action": "Décision"})
        fig.update_layout(xaxis_type="category",
                          plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
        _top_totals = top_ports.groupby("port_lbl")["count"].sum()
        st.markdown(
            f"📌 **{_top_totals.idxmax()}** est le port le plus ciblé "
            f"— **{int(_top_totals.max()):,}** connexions au total."
        )

    # Croisement catégorie × action
    st.subheader("Catégorie de port × Décision du pare-feu")
    with st.expander("💡 Comment lire ce graphique ?"):
        st.markdown("""
Ce graphique croise les **catégories de ports** avec la **décision du pare-feu**.
Il permet de voir, par exemple, si les tentatives sur les ports *Well-known* sont majoritairement
autorisées (trafic légitime vers des services web) ou bloquées (tentatives d'intrusion).
""")
    cross = (df_p.groupby(["port_category", "action"], as_index=False)
             .size().rename(columns={"size": "count"}))
    _ct = cross.groupby("port_category")["count"].transform("sum")
    cross["pct"]   = (cross["count"] / _ct * 100).round(1)
    cross["label"] = cross["pct"].apply(lambda x: f"{x:.0f}%")
    fig = px.bar(cross, x="port_category", y="count", color="action", barmode="group",
                 text="label",
                 color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                 labels={"port_category": "Catégorie de port", "count": "Connexions", "action": "Décision"})
    fig.update_traces(
        textfont_size=11, textposition="outside",
        hovertemplate="<b>%{x}</b> · %{data.name}<br>Connexions : <b>%{y:,}</b><br>Part de la catégorie : <b>%{text}</b><extra></extra>",
    )
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=0, r=0, t=30, b=0), uniformtext_minsize=8)
    st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# TAB 3 — IP EXPLORER
# =============================================================================

with t3:
    st.subheader("Exploration interactive par IP source")
    with st.expander("💡 Comment lire ce graphique ?"):
        st.markdown("""
Chaque **point** représente une IP source différente. Sa position et son apparence donnent des informations :

- **Axe horizontal (X)** : nombre de destinations distinctes contactées par cette IP.
  Une IP qui contacte beaucoup de destinations différentes peut être en train de *scanner* le réseau.
- **Axe vertical (Y)** : volume total de connexions émises par cette IP.
- **Taille du point** : plus le point est grand, plus l'IP a émis de connexions.
- **Couleur** : du 🟢 vert (0% de Deny) au 🔴 rouge (100% de Deny).
  Une IP rouge = toutes ses connexions sont bloquées → comportement très suspect.
  Une IP verte = toutes ses connexions sont autorisées → probablement légitime.

**Cas à surveiller** : points rouges, grands, et/ou très à droite (beaucoup de destinations).
""")

    summary = ip_traffic_summary(df)

    if summary.empty:
        st.warning("Aucune donnée avec les filtres actuels.")
    else:
        max_f = int(summary["n_flows"].max())
        min_f = int(summary["n_flows"].min())
        max_d = int(summary["n_dst"].max())

        col_s, col_m = st.columns([3, 1])
        with col_s:
            threshold = st.slider("Afficher les IPs avec au moins N connexions",
                                  min_value=min_f, max_value=max_f,
                                  value=min_f, step=max(1, (max_f - min_f) // 50))
        filtered = summary[summary["n_flows"] >= threshold]
        with col_m:
            st.metric("IPs affichées", f"{len(filtered):,} / {len(summary):,}")

        # Seuil de détection scanning (ligne verte verticale)
        col_d, col_nd = st.columns([3, 1])
        with col_d:
            dst_threshold = st.slider(
                "🟢 Seuil scanning — destinations contactées",
                min_value=1, max_value=max(2, max_d),
                value=max(1, int(filtered["n_dst"].quantile(0.75))),
                help=(
                    "Ligne verte : les IPs à droite de ce seuil ont contacté un grand nombre "
                    "de destinations distinctes — comportement typique d'un scan réseau."
                ),
            )
        with col_nd:
            n_scanners = int((filtered["n_dst"] >= dst_threshold).sum())
            st.metric("IPs ≥ seuil", f"{n_scanners:,}", help="IPs à droite de la ligne verte.")

        fig = px.scatter(
            filtered, x="n_dst", y="n_flows",
            color="deny_pct", size="n_flows", size_max=40,
            hover_name="src_ip",
            hover_data={"n_dst": True, "n_flows": True,
                        "n_deny": True, "n_permit": True,
                        "deny_pct": ":.1f", "src_ip": False},
            labels={"n_dst":    "Destinations uniques contactées",
                    "n_flows":  "Volume total de connexions",
                    "deny_pct": "% Deny (rouge = suspect)"},
            color_continuous_scale="RdYlGn_r", range_color=[0, 100],
        )
        fig.add_vline(
            x=dst_threshold, line_dash="solid", line_color="#4ADE80", line_width=2,
            annotation_text="Seuil scanning",
            annotation_position="top left",
            annotation_font_color="#4ADE80",
        )
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

        high_deny = filtered[filtered["deny_pct"] >= 50]
        scanners  = filtered[filtered["n_dst"] >= dst_threshold].sort_values("n_dst", ascending=False)

        st.markdown("#### 🚨 Alertes détectées")
        _a1, _a2 = st.columns(2)

        with _a1:
            st.markdown("**⚠️ Taux de blocage élevé**")
            st.caption(
                "Signal *pare-feu* : ces IPs sont bloquées sur ≥ 50 % de leurs connexions. "
                "Le réseau les repousse → tentatives d'intrusion probables."
            )
            if not high_deny.empty:
                st.warning(
                    f"**{len(high_deny)} IP(s)** bloquées à > 50 % : "
                    + ", ".join(f"`{ip}`" for ip in high_deny.head(5)["src_ip"])
                    + (" …" if len(high_deny) > 5 else "")
                )
            else:
                st.success("Aucune IP avec un taux de blocage élevé.")

        with _a2:
            st.markdown("**🔍 Comportement de scan**")
            st.caption(
                f"Signal *comportemental* : ces IPs contactent ≥ {dst_threshold} destinations "
                "distinctes, indépendamment de ce que le pare-feu décide. "
                "Reconnaissance réseau ou balayage de ports possible."
            )
            if n_scanners > 0:
                st.info(
                    f"**{n_scanners} IP(s)** ont sondé ≥ {dst_threshold} destinations : "
                    + ", ".join(f"`{ip}`" for ip in scanners.head(5)["src_ip"])
                    + (" …" if n_scanners > 5 else "")
                )
            else:
                st.success("Aucune IP au-delà du seuil de scan.")

        st.divider()
        st.subheader("Détail d'une IP source")
        selected = st.selectbox(
            "Sélectionner une IP à analyser",
            filtered.sort_values("n_flows", ascending=False)["src_ip"].tolist(),
        )
        if selected:
            row = filtered[filtered["src_ip"] == selected].iloc[0]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Connexions totales", f"{row['n_flows']:,}")
            c2.metric("Destinations uniques", f"{row['n_dst']:,}")
            c3.metric("Autorisées (Permit)", f"{row['n_permit']:,}")
            c4.metric("Bloquées (Deny)",     f"{row['n_deny']:,}")

            ip_df = df[df["src_ip"] == selected]
            cl, cr = st.columns(2)

            with cl:
                dst_c = (ip_df.groupby(["dst_ip", "action"], as_index=False)
                         .size().rename(columns={"size": "count"})
                         .sort_values("count", ascending=False).head(10))
                fig2 = px.bar(dst_c, x="dst_ip", y="count", color="action",
                              color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                              labels={"dst_ip": "IP destination", "count": "Connexions", "action": "Décision"},
                              title=f"Top 10 destinations contactées par {selected}")
                fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                   margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig2, use_container_width=True)

            with cr:
                port_c = (ip_df.groupby(["dst_port", "action"], as_index=False)
                          .size().rename(columns={"size": "count"})
                          .sort_values("count", ascending=False).head(10))
                fig3 = px.bar(port_c, x="dst_port", y="count", color="action",
                              color_discrete_map={"Permit": "#4ADE80", "Deny": "#F87171"},
                              labels={"dst_port": "Port ciblé", "count": "Connexions", "action": "Décision"},
                              title=f"Top 10 ports ciblés par {selected}")
                fig3.update_layout(xaxis_type="category",
                                   plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                   margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig3, use_container_width=True)
