"""
Generate sample NSL-KDD format logs for testing the platform.
Usage: python scripts/generate_sample_logs.py

Outputs: data/sample_logs.csv
Fields match NSL-KDD feature names exactly so they can be
fed directly into the prediction pipeline.
"""

import csv
import random
import os
import numpy as np

# =========================================================
# REPRODUCIBILITY
# =========================================================

random.seed(42)
np.random.seed(42)

# =========================================================
# NSL-KDD NUMERIC FEATURES (38 fields, no categoricals here)
# =========================================================

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

# Categorical fields — valid values from the real NSL-KDD dataset
PROTOCOL_TYPES = ["tcp", "udp", "icmp"]
FLAGS = ["SF", "S0", "REJ", "RSTO", "SH", "RSTR", "S1", "S2", "S3", "OTH"]
SERVICES = [
    "http", "ftp", "smtp", "ssh", "dns", "ftp_data",
    "telnet", "pop_3", "imap4", "finger", "other"
]

ALL_FIELDS = ["duration", "protocol_type", "service", "flag",
              "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
              "hot", "num_failed_logins", "logged_in", "num_compromised",
              "root_shell", "su_attempted", "num_root", "num_file_creations",
              "num_shells", "num_access_files", "num_outbound_cmds",
              "is_host_login", "is_guest_login", "count", "srv_count",
              "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
              "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
              "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
              "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
              "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
              "dst_host_srv_serror_rate", "dst_host_rerror_rate",
              "dst_host_srv_rerror_rate", "label"]

# =========================================================
# ATTACK PROFILES
# Each profile defines realistic distributions per attack type
# based on NSL-KDD dataset statistics.
# =========================================================

ATTACK_PROFILES = {

    "Benign": {
        "protocol_type": ["tcp", "udp"],
        "service":        ["http", "ftp_data", "smtp", "dns", "other"],
        "flag":           ["SF"],
        "numeric": {
            "duration":            lambda: int(np.random.exponential(50)),
            "src_bytes":           lambda: int(np.random.exponential(5000)),
            "dst_bytes":           lambda: int(np.random.exponential(3000)),
            "land":                lambda: 0,
            "wrong_fragment":      lambda: 0,
            "urgent":              lambda: 0,
            "hot":                 lambda: int(np.random.poisson(0.5)),
            "num_failed_logins":   lambda: 0,
            "logged_in":           lambda: 1,
            "num_compromised":     lambda: 0,
            "root_shell":          lambda: 0,
            "su_attempted":        lambda: 0,
            "num_root":            lambda: 0,
            "num_file_creations":  lambda: int(np.random.poisson(0.3)),
            "num_shells":          lambda: 0,
            "num_access_files":    lambda: int(np.random.poisson(0.2)),
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: 0,
            "count":               lambda: int(np.random.uniform(1, 50)),
            "srv_count":           lambda: int(np.random.uniform(1, 50)),
            "serror_rate":         lambda: round(np.random.uniform(0.0, 0.05), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.05), 2),
            "rerror_rate":         lambda: round(np.random.uniform(0.0, 0.05), 2),
            "srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.05), 2),
            "same_srv_rate":       lambda: round(np.random.uniform(0.7, 1.0), 2),
            "diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.1), 2),
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_count":      lambda: int(np.random.uniform(50, 255)),
            "dst_host_srv_count":  lambda: int(np.random.uniform(50, 255)),
            "dst_host_same_srv_rate":       lambda: round(np.random.uniform(0.7, 1.0), 2),
            "dst_host_diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_same_src_port_rate":  lambda: round(np.random.uniform(0.0, 0.2), 2),
            "dst_host_srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_rerror_rate":         lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.05), 2),
        }
    },

    "DoS": {
        "protocol_type": ["tcp", "icmp"],
        "service":        ["http", "smtp", "ftp", "other"],
        "flag":           ["S0", "SF", "RSTO"],
        "numeric": {
            "duration":            lambda: int(np.random.uniform(0, 5)),
            "src_bytes":           lambda: int(np.random.exponential(1000)),
            "dst_bytes":           lambda: 0,
            "land":                lambda: 0,
            "wrong_fragment":      lambda: int(np.random.choice([0, 1, 3])),
            "urgent":              lambda: 0,
            "hot":                 lambda: 0,
            "num_failed_logins":   lambda: 0,
            "logged_in":           lambda: 0,
            "num_compromised":     lambda: 0,
            "root_shell":          lambda: 0,
            "su_attempted":        lambda: 0,
            "num_root":            lambda: 0,
            "num_file_creations":  lambda: 0,
            "num_shells":          lambda: 0,
            "num_access_files":    lambda: 0,
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: 0,
            "count":               lambda: int(np.random.uniform(200, 512)),
            "srv_count":           lambda: int(np.random.uniform(200, 512)),
            "serror_rate":         lambda: round(np.random.uniform(0.8, 1.0), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.8, 1.0), 2),
            "rerror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "same_srv_rate":       lambda: round(np.random.uniform(0.9, 1.0), 2),
            "diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.05), 2),
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_count":      lambda: int(np.random.uniform(200, 255)),
            "dst_host_srv_count":  lambda: int(np.random.uniform(200, 255)),
            "dst_host_same_srv_rate":       lambda: round(np.random.uniform(0.9, 1.0), 2),
            "dst_host_diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_same_src_port_rate":  lambda: round(np.random.uniform(0.8, 1.0), 2),
            "dst_host_srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.8, 1.0), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.8, 1.0), 2),
            "dst_host_rerror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
        }
    },

    "DDoS": {
        "protocol_type": ["icmp", "udp"],
        "service":        ["other", "http", "dns"],
        "flag":           ["SF", "S0"],
        "numeric": {
            "duration":            lambda: 0,
            "src_bytes":           lambda: int(np.random.uniform(1000, 60000)),
            "dst_bytes":           lambda: 0,
            "land":                lambda: 0,
            "wrong_fragment":      lambda: 0,
            "urgent":              lambda: 0,
            "hot":                 lambda: 0,
            "num_failed_logins":   lambda: 0,
            "logged_in":           lambda: 0,
            "num_compromised":     lambda: 0,
            "root_shell":          lambda: 0,
            "su_attempted":        lambda: 0,
            "num_root":            lambda: 0,
            "num_file_creations":  lambda: 0,
            "num_shells":          lambda: 0,
            "num_access_files":    lambda: 0,
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: 0,
            "count":               lambda: 511,
            "srv_count":           lambda: 511,
            "serror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "rerror_rate":         lambda: 0.0,
            "srv_rerror_rate":     lambda: 0.0,
            "same_srv_rate":       lambda: 1.0,
            "diff_srv_rate":       lambda: 0.0,
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.05), 2),
            "dst_host_count":      lambda: 255,
            "dst_host_srv_count":  lambda: 255,
            "dst_host_same_srv_rate":       lambda: 1.0,
            "dst_host_diff_srv_rate":       lambda: 0.0,
            "dst_host_same_src_port_rate":  lambda: 1.0,
            "dst_host_srv_diff_host_rate":  lambda: 0.0,
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_rerror_rate":         lambda: 0.0,
            "dst_host_srv_rerror_rate":     lambda: 0.0,
        }
    },

    "PortScan": {
        "protocol_type": ["tcp"],
        "service":        ["other", "http", "ftp", "smtp", "ssh"],
        "flag":           ["S0", "REJ", "RSTR", "SH"],
        "numeric": {
            "duration":            lambda: 0,
            "src_bytes":           lambda: 0,
            "dst_bytes":           lambda: 0,
            "land":                lambda: 0,
            "wrong_fragment":      lambda: 0,
            "urgent":              lambda: 0,
            "hot":                 lambda: 0,
            "num_failed_logins":   lambda: 0,
            "logged_in":           lambda: 0,
            "num_compromised":     lambda: 0,
            "root_shell":          lambda: 0,
            "su_attempted":        lambda: 0,
            "num_root":            lambda: 0,
            "num_file_creations":  lambda: 0,
            "num_shells":          lambda: 0,
            "num_access_files":    lambda: 0,
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: 0,
            "count":               lambda: int(np.random.uniform(1, 30)),
            "srv_count":           lambda: int(np.random.uniform(1, 30)),
            "serror_rate":         lambda: round(np.random.uniform(0.0, 0.6), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.6), 2),
            "rerror_rate":         lambda: round(np.random.uniform(0.3, 1.0), 2),
            "srv_rerror_rate":     lambda: round(np.random.uniform(0.3, 1.0), 2),
            "same_srv_rate":       lambda: round(np.random.uniform(0.0, 0.3), 2),
            "diff_srv_rate":       lambda: round(np.random.uniform(0.5, 1.0), 2),
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.1, 0.5), 2),
            "dst_host_count":      lambda: int(np.random.uniform(1, 60)),
            "dst_host_srv_count":  lambda: int(np.random.uniform(1, 30)),
            "dst_host_same_srv_rate":       lambda: round(np.random.uniform(0.0, 0.2), 2),
            "dst_host_diff_srv_rate":       lambda: round(np.random.uniform(0.5, 1.0), 2),
            "dst_host_same_src_port_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_srv_diff_host_rate":  lambda: round(np.random.uniform(0.1, 0.5), 2),
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.0, 0.5), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.5), 2),
            "dst_host_rerror_rate":         lambda: round(np.random.uniform(0.3, 1.0), 2),
            "dst_host_srv_rerror_rate":     lambda: round(np.random.uniform(0.3, 1.0), 2),
        }
    },

    "BruteForce": {
        "protocol_type": ["tcp"],
        "service":        ["ftp", "ssh", "telnet", "smtp", "imap4", "pop_3"],
        "flag":           ["SF", "RSTO"],
        "numeric": {
            "duration":            lambda: int(np.random.uniform(1, 20)),
            "src_bytes":           lambda: int(np.random.uniform(100, 2000)),
            "dst_bytes":           lambda: int(np.random.uniform(100, 2000)),
            "land":                lambda: 0,
            "wrong_fragment":      lambda: 0,
            "urgent":              lambda: 0,
            "hot":                 lambda: int(np.random.poisson(1)),
            "num_failed_logins":   lambda: int(np.random.uniform(1, 5)),
            "logged_in":           lambda: 0,
            "num_compromised":     lambda: 0,
            "root_shell":          lambda: 0,
            "su_attempted":        lambda: 0,
            "num_root":            lambda: 0,
            "num_file_creations":  lambda: 0,
            "num_shells":          lambda: 0,
            "num_access_files":    lambda: 0,
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: int(np.random.choice([0, 1])),
            "count":               lambda: int(np.random.uniform(5, 100)),
            "srv_count":           lambda: int(np.random.uniform(5, 100)),
            "serror_rate":         lambda: round(np.random.uniform(0.0, 0.2), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.2), 2),
            "rerror_rate":         lambda: round(np.random.uniform(0.0, 0.3), 2),
            "srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.3), 2),
            "same_srv_rate":       lambda: round(np.random.uniform(0.5, 1.0), 2),
            "diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.2), 2),
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_count":      lambda: int(np.random.uniform(10, 255)),
            "dst_host_srv_count":  lambda: int(np.random.uniform(10, 255)),
            "dst_host_same_srv_rate":       lambda: round(np.random.uniform(0.5, 1.0), 2),
            "dst_host_diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.2), 2),
            "dst_host_same_src_port_rate":  lambda: round(np.random.uniform(0.0, 0.5), 2),
            "dst_host_srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.0, 0.2), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.2), 2),
            "dst_host_rerror_rate":         lambda: round(np.random.uniform(0.0, 0.3), 2),
            "dst_host_srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.3), 2),
        }
    },

    "Exploit": {
        "protocol_type": ["tcp"],
        "service":        ["ftp", "telnet", "finger", "ssh", "other"],
        "flag":           ["SF", "RSTO", "S1"],
        "numeric": {
            "duration":            lambda: int(np.random.uniform(0, 30)),
            "src_bytes":           lambda: int(np.random.uniform(200, 8000)),
            "dst_bytes":           lambda: int(np.random.uniform(200, 8000)),
            "land":                lambda: 0,
            "wrong_fragment":      lambda: 0,
            "urgent":              lambda: int(np.random.choice([0, 0, 0, 1])),
            "hot":                 lambda: int(np.random.uniform(2, 30)),
            "num_failed_logins":   lambda: 0,
            "logged_in":           lambda: int(np.random.choice([0, 1])),
            "num_compromised":     lambda: int(np.random.uniform(1, 10)),
            "root_shell":          lambda: int(np.random.choice([0, 0, 1])),
            "su_attempted":        lambda: int(np.random.choice([0, 1])),
            "num_root":            lambda: int(np.random.uniform(0, 5)),
            "num_file_creations":  lambda: int(np.random.uniform(0, 5)),
            "num_shells":          lambda: int(np.random.choice([0, 1])),
            "num_access_files":    lambda: int(np.random.uniform(0, 5)),
            "num_outbound_cmds":   lambda: 0,
            "is_host_login":       lambda: 0,
            "is_guest_login":      lambda: 0,
            "count":               lambda: int(np.random.uniform(1, 20)),
            "srv_count":           lambda: int(np.random.uniform(1, 20)),
            "serror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "rerror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "same_srv_rate":       lambda: round(np.random.uniform(0.5, 1.0), 2),
            "diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.2), 2),
            "srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_count":      lambda: int(np.random.uniform(1, 100)),
            "dst_host_srv_count":  lambda: int(np.random.uniform(1, 100)),
            "dst_host_same_srv_rate":       lambda: round(np.random.uniform(0.3, 1.0), 2),
            "dst_host_diff_srv_rate":       lambda: round(np.random.uniform(0.0, 0.3), 2),
            "dst_host_same_src_port_rate":  lambda: round(np.random.uniform(0.0, 0.3), 2),
            "dst_host_srv_diff_host_rate":  lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_serror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_srv_serror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_rerror_rate":         lambda: round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_srv_rerror_rate":     lambda: round(np.random.uniform(0.0, 0.1), 2),
        }
    },
}

# =========================================================
# ROW GENERATOR
# =========================================================

def generate_row(attack_type: str) -> dict:
    profile = ATTACK_PROFILES[attack_type]
    row = {}

    # Categorical fields
    row["protocol_type"] = random.choice(profile["protocol_type"])
    row["service"]       = random.choice(profile["service"])
    row["flag"]          = random.choice(profile["flag"])

    # Numeric fields from lambdas
    for field, fn in profile["numeric"].items():
        row[field] = fn()

    row["label"] = attack_type
    return row


# =========================================================
# MAIN
# =========================================================

def main():
    output_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "sample_logs.csv"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # -------------------------------------------------------
    # Class balance: more benign than attacks (realistic ratio)
    # -------------------------------------------------------
    counts = {
        "Benign":     200,
        "DoS":         60,
        "DDoS":        60,
        "PortScan":    50,
        "BruteForce":  50,
        "Exploit":     30,
    }

    rows = []
    for attack_type, count in counts.items():
        for _ in range(count):
            rows.append(generate_row(attack_type))

    random.shuffle(rows)

    # -------------------------------------------------------
    # Write CSV
    # -------------------------------------------------------
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ALL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    threats = sum(1 for r in rows if r["label"] != "Benign")
    print(f"✅ Generated {total} logs ({threats} threats, {total - threats} benign)")
    print(f"📄 Output: {output_path}")
    print("\nBreakdown:")
    for attack_type, count in counts.items():
        print(f"  {attack_type:<15} {count}")


if __name__ == "__main__":
    main()