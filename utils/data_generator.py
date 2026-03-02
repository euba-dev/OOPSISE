"""
Générateur de données fictives simulant des logs iptables.
Remplacer load_data() par la lecture du CSV OPSIE réel quand disponible.

Format des données (§1.2 énoncé OPSIE) :
    timestamp, src_ip, dst_ip, proto, dst_port, action (Permit/Deny),
    policy_id (999 = cleanup), interface_in, interface_out
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

_INTERNAL_NETS = [
    "192.168.1.", "192.168.2.", "10.0.0.", "10.0.1.", "172.16.0.",
    "159.84.1.", "159.84.2.",                # plan d'adressage université
]
_EXTERNAL_NETS = [
    "203.0.113.", "198.51.100.", "185.220.101.",
    "91.108.4.", "77.88.8.", "89.89.56.", "28.12.15.",
]

# Ports pondérés (services décrits dans l'énoncé + registered + dynamic)
_PORT_POOL = (
    [20, 21, 22, 23, 25, 53, 80, 443, 3306, 8080, 8443] * 10
    + list(range(1024, 1200))
    + list(range(49152, 49200))
)

_PROTOCOLS  = ["TCP", "UDP"]
_ACTIONS    = ["Permit", "Deny"]             # format OPSIE (§1.2)
_POLICY_IDS = [str(i) for i in range(1, 16)] + ["999"]   # 999 = cleanup
_INTERFACES = ["eth0", "eth1"]


def _random_ip(prefix_list, rng):
    return f"{rng.choice(prefix_list)}{rng.integers(1, 255)}"


def generate_iptables_logs(
    n_rows: int = 10000,
    start: datetime | None = None,
    hours_span: int = 168,
    deny_ratio: float = 0.18,
    seed: int = 42,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    if start is None:
        start = datetime.now() - timedelta(hours=hours_span)

    n_business = n_rows - n_rows // 2
    rng1 = np.random.default_rng(seed + 1)
    rng2 = np.random.default_rng(seed + 2)

    # 50% trafic uniforme sur toute la période
    uniform_offsets = rng1.integers(0, hours_span * 3600, n_rows // 2)

    # 50% heures ouvrées (8h–20h) réparties sur tous les jours de la période
    n_days = max(1, hours_span // 24)
    days        = rng2.integers(0, n_days, n_business)
    hour_secs   = rng2.integers(8 * 3600, 20 * 3600, n_business)
    business_offsets = (days * 24 * 3600 + hour_secs).clip(0, hours_span * 3600 - 1)

    offsets = rng.choice(
        np.concatenate([uniform_offsets, business_offsets]),
        size=n_rows,
        replace=False,
    )
    timestamps  = [start + timedelta(seconds=int(s)) for s in offsets]
    src_ips     = [_random_ip(_INTERNAL_NETS, rng) for _ in range(n_rows)]
    dst_ips     = [
        _random_ip(_EXTERNAL_NETS if rng.random() > 0.3 else _INTERNAL_NETS, rng)
        for _ in range(n_rows)
    ]
    dst_ports   = rng.choice(_PORT_POOL, size=n_rows).astype(int)
    protos      = rng.choice(_PROTOCOLS,  size=n_rows, p=[0.75, 0.25])
    actions     = rng.choice(_ACTIONS,    size=n_rows, p=[1 - deny_ratio, deny_ratio])
    policy_ids  = rng.choice(_POLICY_IDS, size=n_rows)
    iface_in    = rng.choice(_INTERFACES, size=n_rows, p=[0.7, 0.3])
    iface_out   = rng.choice(_INTERFACES, size=n_rows, p=[0.4, 0.6])

    df = pd.DataFrame({
        "timestamp":     pd.to_datetime(timestamps),
        "src_ip":        src_ips,
        "dst_ip":        dst_ips,
        "dst_port":      dst_ports,
        "proto":         protos,
        "action":        actions,
        "policy_id":     policy_ids,
        "interface_in":  iface_in,
        "interface_out": iface_out,
    })

    return df.sort_values("timestamp").reset_index(drop=True)


def load_data(csv_path: str | None = None, **kwargs) -> pd.DataFrame:
    """Point d'entrée legacy — préférer utils.data_loader.get_data()."""
    if csv_path:
        df = pd.read_csv(csv_path, parse_dates=["timestamp"])
        required = {"timestamp", "src_ip", "dst_ip", "dst_port", "proto", "action", "policy_id"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Colonnes manquantes : {missing}")
        return df
    return generate_iptables_logs(**kwargs)
