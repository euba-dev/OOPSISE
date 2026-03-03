"""
CHALLENGE OPSIE x SISE 2026 — Point d'entrée
streamlit run main.py
"""

import streamlit as st

from utils.ui import PAGE_CONFIG

st.set_page_config(page_title="OPSIE x SISE 2026", **PAGE_CONFIG)


def page_accueil():
    st.title("🛡️ OPSIE x SISE — Analyse de logs Firewall")
    st.caption("Challenge 2026 · Master SISE · Université Lumière Lyon 2")
    st.divider()

    st.markdown("""
### À quoi sert cette application ?

Dans le cadre du **Challenge OPSIE x SISE**, cette application permet d'explorer et d'analyser
des **logs** produits par un **pare-feu iptables**.

---


Pour chaque connexion qui tente de passer, le pare-feu applique
des **règles** et prend une décision :

- ✅ **Permit** — la connexion est **autorisée** à passer
- 🚫 **Deny** — la connexion est **bloquée**

Nous disposons donc des logs qui documentent qui a voulu se connecter, à quoi, sur quel port, avec quel protocole, et la décision prise par le pare-feu.

---

#### 📖 Mini-Glossaire 

| Terme | Définition |
|---|---|
| **Flux** | Une tentative de connexion réseau (ex. : un ordinateur envoie une requête vers un serveur) |
| **IP source** | L'adresse de la machine qui initie la connexion |
| **IP destination** | L'adresse de la machine cible |
| **Port** | La "porte" du service ciblé : 80 = HTTP (web), 443 = HTTPS (web sécurisé), 22 = SSH (administration distante)… |
| **Protocole** | Le "langage" utilisé : TCP (connexions fiables) ou UDP (flux rapides, ex. vidéo/DNS) |
| **Règle (policy_id)** | Numéro de la règle du pare-feu qui a traité ce flux |
| **Règle 999** | Règle "fourre-tout" (*catch-all*) : bloque automatiquement tout trafic non explicitement autorisé |
| **IP interne** | Adresse appartenant au réseau de l'université (plages 192.168.x.x, 10.x.x.x, 159.84.x.x…) |
| **IP externe** | Adresse venant d'internet, hors du réseau interne |
""")

    st.divider()

    st.markdown("""
### 🗺️ Pages de l'application

| Page | Ce que vous y trouverez |
|---|---|
| 📊 **Dashboard** | Vue d'ensemble : trafic par heure, ports les plus ciblés, IPs les plus actives, règles les plus utilisées |
| 📋 **Données** | Accès aux logs bruts, recherche par IP, export CSV |
| 🤖 **IA & ML** | Détection automatique de comportements suspects (Isolation Forest) et rapport de sécurité généré par Mistral AI |
""")

    st.info(
        "💡 **Conseil de lecture** : utilisez les **filtres dans la barre latérale** (période, heure, protocole, action) "
        "pour affiner l'analyse sur toutes les pages.",
        icon="🔍",
    )



pg = st.navigation([
    st.Page(page_accueil,           title="Accueil",   icon="🏠"),
    st.Page("pages/1_Dashboard.py", title="Dashboard", icon="📊"),
    st.Page("pages/2_Donnees.py",   title="Données",   icon="📋"),
    st.Page("pages/3_IA_ML.py",     title="IA & ML",   icon="🤖"),
])
pg.run()
