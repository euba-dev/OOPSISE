"""
Fonctions utilitaires métier pour l'analyse des logs iptables.
Actions attendues : "Permit" / "Deny" (format OPSIE §1.2).
"""

import pandas as pd

# Préfixes internes : RFC 1918 + plan d'adressage université Lyon 2 (159.84.x.x)
_INTERNAL_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "159.84.",
)


# ---------------------------------------------------------------------------
# Classification des ports (RFC 6056 / IANA)
# ---------------------------------------------------------------------------

def classify_port(port: int) -> str:
    if not isinstance(port, (int, float)):
        return "Unknown"
    port = int(port)
    if port < 0 or port > 65535:
        return "Unknown"
    if port <= 1023:
        return "Well-known"
    if port <= 49151:
        return "Registered"
    return "Dynamic/Private"


def add_port_category(df: pd.DataFrame, port_col: str = "dst_port") -> pd.DataFrame:
    df = df.copy()
    df["port_category"] = df[port_col].apply(classify_port)
    return df


# ---------------------------------------------------------------------------
# Agrégations
# ---------------------------------------------------------------------------

def compute_hourly_traffic(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    return (
        df.groupby("hour", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("hour")
    )


def compute_deny_ratio(df: pd.DataFrame, action_col: str = "action") -> float:
    """Retourne le pourcentage de flux Deny (0–100)."""
    if df.empty:
        return 0.0
    return round(100 * (df[action_col] == "Deny").sum() / len(df), 2)


def top_src_ips(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    return (
        df.groupby("src_ip", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )


def port_category_distribution(df: pd.DataFrame) -> pd.DataFrame:
    if "port_category" not in df.columns:
        df = add_port_category(df)
    return (
        df.groupby("port_category", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
    )


def top_permitted_ports_under_1024(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """TOP n ports < 1024 avec action Permit (§1.5 point 4)."""
    mask = (df["dst_port"] < 1024) & (df["action"] == "Permit")
    return (
        df[mask]
        .groupby("dst_port", as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )


def external_ip_accesses(df: pd.DataFrame) -> pd.DataFrame:
    """Flux dont l'IP source est hors plan d'adressage interne (§1.5 point 4)."""
    mask = ~df["src_ip"].apply(lambda ip: any(ip.startswith(p) for p in _INTERNAL_PREFIXES))
    return df[mask].copy()


def ip_traffic_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Par IP source : nb destinations uniques, nb flux, nb Deny, nb Permit.
    Base du scatter interactif (§1.5 point 3).
    """
    agg = (
        df.groupby("src_ip")
        .agg(
            n_dst  =("dst_ip", "nunique"),
            n_flows=("dst_ip", "count"),
            n_deny =("action", lambda x: (x == "Deny").sum()),
        )
        .reset_index()
    )
    agg["n_permit"] = agg["n_flows"] - agg["n_deny"]
    agg["deny_pct"] = (agg["n_deny"] / agg["n_flows"] * 100).round(1)
    return agg.sort_values("n_flows", ascending=False).reset_index(drop=True)
