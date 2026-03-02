"""
import_sample.py
----------------
Lit le fichier CSV brut fourni par les collègues (echantillon_logs.csv)
et l'importe dans une base SQLite exploitable par l'application.

Usage :
    python import_sample.py

La base SQLite est créée dans OOPSISE/data/logs.db.
Pour activer la source SQL dans l'app, mettre dans .env :
    DATA_SOURCE=sql
    SQL_URL=sqlite:///data/logs.db
    SQL_QUERY=SELECT * FROM iptables_logs
"""

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# Chemins
# ---------------------------------------------------------------------------
BASE_DIR  = Path(__file__).parent.parent   # OOPSISE/utils/ → OOPSISE/
CSV_PATH  = BASE_DIR / "data" / "echantillon_logs.csv"
DB_PATH   = BASE_DIR / "data" / "logs.db"

# Année à utiliser pour reconstruire le timestamp (absent du fichier source)
YEAR = datetime.now().year

# ---------------------------------------------------------------------------
# 1. Lecture du CSV brut
# ---------------------------------------------------------------------------
df_raw = pd.read_csv(CSV_PATH)
print(f"Lignes lues : {len(df_raw)}")
print(f"Colonnes    : {list(df_raw.columns)}")

# ---------------------------------------------------------------------------
# 2. Reconstruction du timestamp
#    Format source : month="Mar", day=2, time="16:19:32"
#    → "2025-Mar-02 16:19:32"
# ---------------------------------------------------------------------------
df_raw["timestamp"] = pd.to_datetime(
    df_raw["month"].astype(str) + " "
    + df_raw["day"].astype(str) + " "
    + df_raw["time"].astype(str)
    + f" {YEAR}",
    format="%b %d %H:%M:%S %Y",
)

# ---------------------------------------------------------------------------
# 3. Renommage et normalisation des colonnes
#    Colonnes de l'app : timestamp, src_ip, dst_ip, proto, dst_port,
#                        action (Permit/Deny), policy_id
# ---------------------------------------------------------------------------
df = pd.DataFrame({
    "timestamp": df_raw["timestamp"],
    "src_ip":    df_raw["src"],
    "dst_ip":    df_raw["dst"],
    "proto":     df_raw["proto"],
    "dst_port":  df_raw["dpt"].astype(int),
    "action":    df_raw["action"].str.capitalize(),   # PERMIT → Permit, DENY → Deny
    "policy_id": df_raw["rule"].astype(str),
})

# Validation rapide
assert df["action"].isin(["Permit", "Deny"]).all(), "Valeurs d'action inattendues !"
print(f"\nAperçu après transformation :")
print(df.head())
print(f"\nDistribution actions :\n{df['action'].value_counts()}")

# ---------------------------------------------------------------------------
# 4. Création de la base SQLite et insertion
# ---------------------------------------------------------------------------
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS iptables_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        src_ip      TEXT    NOT NULL,
        dst_ip      TEXT    NOT NULL,
        proto       TEXT    NOT NULL,
        dst_port    INTEGER NOT NULL,
        action      TEXT    NOT NULL CHECK(action IN ('Permit', 'Deny')),
        policy_id   TEXT    NOT NULL
    )
""")

# Vider la table avant réinsertion 
cursor.execute("DELETE FROM iptables_logs")

df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
df.to_sql("iptables_logs", conn, if_exists="append", index=False)

conn.commit()
conn.close()

print(f"\n✅ {len(df)} lignes insérées dans {DB_PATH}")
print("Pour activer dans l'app, mettre dans .env :")
print("  DATA_SOURCE=sql")
print(f"  SQL_URL=sqlite:///data/logs.db")
print("  SQL_QUERY=SELECT * FROM iptables_logs")
