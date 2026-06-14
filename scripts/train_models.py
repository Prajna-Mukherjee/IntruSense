"""
NSL-KDD Training Pipeline
Trains XGBoost + Isolation Forest + Autoencoder on NSL-KDD dataset.
Usage: python scripts/train_models.py --data /path/to/nsl-kdd/
Expected files: KDDTrain+.txt or KDDTrain+.csv
"""

import os
import argparse
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import IsolationForest
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(BASE_DIR, "..", "backend", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# =========================================================
# NSL-KDD COLUMN NAMES (41 features + label + difficulty)
# =========================================================

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
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
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty"
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# =========================================================
# LABEL NORMALIZATION
# =========================================================

def normalize_label(label: str) -> str:
    label = str(label).lower().strip().rstrip(".")

    if label == "normal":
        return "Benign"

    dos_attacks = {
        "back", "land", "neptune", "pod", "smurf", "teardrop",
        "apache2", "udpstorm", "processtable", "worm"
    }
    if label in dos_attacks:
        if label in {"smurf", "neptune"}:
            return "DDoS"
        return "DoS"

    probe_attacks = {"ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"}
    if label in probe_attacks:
        return "PortScan"

    r2l_attacks = {
        "ftp_write", "guess_passwd", "imap", "multihop", "phf",
        "spy", "warezclient", "warezmaster", "xlock", "xsnoop",
        "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"
    }
    if label in r2l_attacks:
        return "BruteForce"

    u2r_attacks = {
        "buffer_overflow", "loadmodule", "perl", "rootkit",
        "ps", "sqlattack", "xterm"
    }
    if label in u2r_attacks:
        return "Exploit"

    c2_attacks = {"c2", "dns_beacon", "http_beacon", "icmp_beacon"}
    if label in c2_attacks:
        return "C2"

    lateral_attacks = {"lateralmovement", "smb_lateral", "pass_the_hash", "wmi_lateral"}
    if label in lateral_attacks:
        return "LateralMovement"

    exfil_attacks = {"exfiltration", "dns_exfil", "ftp_exfil", "http_exfil"}
    if label in exfil_attacks:
        return "Exfiltration"

    web_attacks = {"webattack", "sqli", "xss", "path_traversal", "csrf"}
    if label in web_attacks:
        return "WebAttack"

    return "Unknown"


# =========================================================
# SYNTHETIC DATA GENERATOR
# Generates realistic NSL-KDD format samples for 4 modern
# attack classes not present in the original dataset.
# Feature distributions are based on published network
# traffic research for each attack category.
# =========================================================

def generate_synthetic_samples(feature_cols_after_encoding: list = None) -> pd.DataFrame:
    """
    Returns a DataFrame with NSL-KDD base columns + label.
    Categorical columns are raw strings (encoded later by encode_categoricals).
    500 samples per class — small enough to not dominate training.
    """
    np.random.seed(99)
    rows = []

    def _base_row():
        """Start with a neutral base and override per attack type."""
        return {
            "duration": 0, "protocol_type": "tcp", "service": "other", "flag": "SF",
            "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
            "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
            "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
            "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
            "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
            "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0, "dst_host_count": 1, "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
        }

    N = 500

    # ----------------------------------------------------------
    # C2 — Command and Control (T1071)
    # Periodic beaconing: regular intervals, small symmetric
    # packets, encrypted channels (https/dns), long duration.
    # ----------------------------------------------------------
    for _ in range(N):
        r = _base_row()
        r.update({
            "duration":           int(np.random.uniform(60, 3600)),
            "protocol_type":      np.random.choice(["tcp", "udp"], p=[0.7, 0.3]),
            "service":            np.random.choice(["http", "domain", "https", "other"], p=[0.3, 0.3, 0.2, 0.2]),
            "flag":               np.random.choice(["SF", "S1"], p=[0.9, 0.1]),
            "src_bytes":          int(np.random.uniform(100, 1500)),
            "dst_bytes":          int(np.random.uniform(100, 1500)),
            "logged_in":          1,
            "count":              int(np.random.uniform(1, 10)),
            "srv_count":          int(np.random.uniform(1, 10)),
            "same_srv_rate":      round(np.random.uniform(0.8, 1.0), 2),
            "diff_srv_rate":      round(np.random.uniform(0.0, 0.1), 2),
            "dst_host_count":     int(np.random.uniform(1, 5)),
            "dst_host_srv_count": int(np.random.uniform(1, 5)),
            "dst_host_same_srv_rate": round(np.random.uniform(0.8, 1.0), 2),
            "label": "c2"
        })
        rows.append(r)

    # ----------------------------------------------------------
    # LateralMovement — (T1021 / T1078)
    # Internal scanning + auth attempts across multiple hosts.
    # High dst_host_count, varied services, moderate error rates.
    # ----------------------------------------------------------
    for _ in range(N):
        r = _base_row()
        r.update({
            "duration":           int(np.random.uniform(0, 60)),
            "protocol_type":      "tcp",
            "service":            np.random.choice(["ssh", "ftp", "telnet", "http", "other"]),
            "flag":               np.random.choice(["SF", "S0", "REJ"], p=[0.5, 0.3, 0.2]),
            "src_bytes":          int(np.random.uniform(200, 5000)),
            "dst_bytes":          int(np.random.uniform(200, 5000)),
            "logged_in":          int(np.random.choice([0, 1])),
            "num_compromised":    int(np.random.uniform(0, 3)),
            "count":              int(np.random.uniform(5, 50)),
            "srv_count":          int(np.random.uniform(2, 20)),
            "diff_srv_rate":      round(np.random.uniform(0.3, 0.8), 2),
            "same_srv_rate":      round(np.random.uniform(0.2, 0.6), 2),
            "rerror_rate":        round(np.random.uniform(0.1, 0.5), 2),
            "dst_host_count":     int(np.random.uniform(10, 100)),
            "dst_host_srv_count": int(np.random.uniform(5, 50)),
            "dst_host_diff_srv_rate": round(np.random.uniform(0.3, 0.8), 2),
            "dst_host_rerror_rate":   round(np.random.uniform(0.1, 0.5), 2),
            "label": "lateralmovement"
        })
        rows.append(r)

    # ----------------------------------------------------------
    # Exfiltration — (T1048)
    # Large outbound data, asymmetric bytes (src >> dst),
    # non-standard ports or DNS tunneling, long sessions.
    # ----------------------------------------------------------
    for _ in range(N):
        r = _base_row()
        r.update({
            "duration":           int(np.random.uniform(30, 600)),
            "protocol_type":      np.random.choice(["tcp", "udp"], p=[0.6, 0.4]),
            "service":            np.random.choice(["ftp", "ftp_data", "domain", "http", "other"], p=[0.3, 0.2, 0.2, 0.2, 0.1]),
            "flag":               "SF",
            "src_bytes":          int(np.random.uniform(50000, 500000)),   # large outbound
            "dst_bytes":          int(np.random.uniform(100, 2000)),       # small response
            "logged_in":          1,
            "num_file_creations": int(np.random.uniform(0, 5)),
            "num_access_files":   int(np.random.uniform(1, 10)),
            "count":              int(np.random.uniform(1, 20)),
            "srv_count":          int(np.random.uniform(1, 10)),
            "same_srv_rate":      round(np.random.uniform(0.5, 1.0), 2),
            "dst_host_count":     int(np.random.uniform(1, 10)),
            "dst_host_same_src_port_rate": round(np.random.uniform(0.5, 1.0), 2),
            "label": "exfiltration"
        })
        rows.append(r)

    # ----------------------------------------------------------
    # WebAttack — (T1190 / T1059)
    # HTTP-based attacks: SQLi, XSS, path traversal.
    # High hot count, short duration, tcp/http, logged in.
    # ----------------------------------------------------------
    for _ in range(N):
        r = _base_row()
        r.update({
            "duration":           int(np.random.uniform(0, 10)),
            "protocol_type":      "tcp",
            "service":            "http",
            "flag":               np.random.choice(["SF", "RSTO"], p=[0.8, 0.2]),
            "src_bytes":          int(np.random.uniform(500, 8000)),
            "dst_bytes":          int(np.random.uniform(200, 5000)),
            "hot":                int(np.random.uniform(5, 30)),
            "logged_in":          int(np.random.choice([0, 1])),
            "num_compromised":    int(np.random.uniform(0, 5)),
            "num_access_files":   int(np.random.uniform(1, 8)),
            "count":              int(np.random.uniform(1, 30)),
            "srv_count":          int(np.random.uniform(1, 30)),
            "same_srv_rate":      round(np.random.uniform(0.7, 1.0), 2),
            "dst_host_count":     int(np.random.uniform(1, 50)),
            "dst_host_srv_count": int(np.random.uniform(1, 50)),
            "dst_host_same_srv_rate": round(np.random.uniform(0.7, 1.0), 2),
            "label": "webattack"
        })
        rows.append(r)

    df_syn = pd.DataFrame(rows)

    # Normalize labels to match training taxonomy
    df_syn["label"] = df_syn["label"].apply(normalize_label)

    print(f"✅ Generated {len(df_syn)} synthetic samples across 4 modern attack classes")
    return df_syn


# =========================================================
# LOAD NSL-KDD
# =========================================================

def load_data(folder: str) -> pd.DataFrame:
    print(f"\n📂 Loading NSL-KDD from: {folder}")

    candidates = [
        "KDDTrain+.txt", "KDDTrain+.csv",
        "KDDTrain+_20Percent.txt", "KDDTrain+_20Percent.csv"
    ]

    path = None
    for name in candidates:
        candidate = os.path.join(folder, name)
        if os.path.exists(candidate):
            path = candidate
            break

    if path is None:
        for f in sorted(os.listdir(folder)):
            if f.endswith(".txt") or f.endswith(".csv"):
                path = os.path.join(folder, f)
                break

    if path is None:
        raise ValueError(f"No NSL-KDD file found in {folder}")

    print(f"➜ Reading: {os.path.basename(path)}")

    df = pd.read_csv(
        path,
        header=None,
        names=NSL_KDD_COLUMNS,
        low_memory=False
    )

    print(f"✅ Loaded shape: {df.shape}")
    return df


# =========================================================
# ENCODE CATEGORICALS
# =========================================================

def encode_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    df = pd.get_dummies(df, columns=CATEGORICAL_COLS, dtype=np.float32)
    return df


# =========================================================
# TRAIN XGBOOST
# =========================================================

def train_xgboost(X_train, y_train, X_test, y_test, num_classes, label_names):
    print("\n🤖 Training XGBoost...")

    model = XGBClassifier(
        objective="multi:softprob",
        num_class=num_classes,
        n_estimators=200,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.80,
        min_child_weight=5,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.5,
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42
    )

    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("\n📊 XGBoost Classification Report:\n")
    print(classification_report(y_test, preds, target_names=label_names))

    path = os.path.join(MODEL_DIR, "xgboost_model.pkl")
    joblib.dump(model, path)
    print(f"✅ Saved XGBoost: {path}")

    return model


# =========================================================
# TRAIN ISOLATION FOREST
# =========================================================

def train_isolation_forest(X_scaled):
    print("\n🌲 Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=300,
        max_samples=0.8,
        contamination=0.07,
        max_features=0.9,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
    joblib.dump(model, path)
    print(f"✅ Saved Isolation Forest: {path}")

    return model


# =========================================================
# TRAIN AUTOENCODER
# =========================================================

def train_autoencoder(X_train_benign, input_dim):
    """
    Train autoencoder on BENIGN traffic only.
    High reconstruction error on unseen data signals an anomaly.
    """
    print("\n🧠 Training Autoencoder (benign traffic only)...")

    try:
        import tensorflow as tf
        from tensorflow.keras.models import Model
        from tensorflow.keras.layers import Input, Dense
        from tensorflow.keras.callbacks import EarlyStopping

        tf.get_logger().setLevel("ERROR")

        encoding_dim = max(16, input_dim // 4)
        hidden_dim   = max(32, input_dim // 2)

        inputs  = Input(shape=(input_dim,))
        # Encoder — gradually compress to latent representation
        x = Dense(hidden_dim, activation="relu")(inputs)
        x = Dense(encoding_dim * 2, activation="relu")(x)
        encoded = Dense(encoding_dim, activation="relu")(x)
        # Decoder — reconstruct from latent
        x = Dense(encoding_dim * 2, activation="relu")(encoded)
        x = Dense(hidden_dim, activation="relu")(x)
        outputs = Dense(input_dim, activation="linear")(x)  # linear: no squash for RobustScaler output

        autoencoder = Model(inputs, outputs, name="autoencoder")
        autoencoder.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
            loss="mse"
        )

        autoencoder.summary()

        early_stop = EarlyStopping(
            monitor="val_loss",
            patience=8,
            restore_best_weights=True,
            min_delta=1e-5
        )

        autoencoder.fit(
            X_train_benign, X_train_benign,
            epochs=80,
            batch_size=256,
            validation_split=0.1,
            callbacks=[early_stop],
            verbose=1
        )

        path = os.path.join(MODEL_DIR, "autoencoder.h5")
        autoencoder.save(path)
        print(f"✅ Saved Autoencoder: {path}")

        return autoencoder

    except ImportError:
        print("⚠️  TensorFlow not installed — skipping autoencoder.")
        print("   Install with: pip install tensorflow")
        return None


# =========================================================
# MAIN
# =========================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Folder containing NSL-KDD files")
    args = parser.parse_args()

    # --- Load ---
    df = load_data(args.data)

    # --- Normalize labels ---
    df["label"] = df["label"].apply(normalize_label)
    df = df[df["label"] != "Unknown"].copy()

    # --- Augment with synthetic modern attack samples ---
    df_synthetic = generate_synthetic_samples()
    df = pd.concat([df, df_synthetic], ignore_index=True)
    print(f"✅ Combined dataset size: {len(df)} rows")

    # --- Drop difficulty ---
    if "difficulty" in df.columns:
        df.drop(columns=["difficulty"], inplace=True)

    # --- Encode categoricals ---
    df = encode_categoricals(df)

    # --- Build feature matrix ---
    feature_cols = [c for c in df.columns if c != "label"]

    X = df[feature_cols].copy()
    y_raw = df["label"].copy()

    # --- Label encoding ---
    labels = sorted(y_raw.unique())
    label_map = {l: i for i, l in enumerate(labels)}
    reverse_map = {i: l for l, i in label_map.items()}

    joblib.dump(reverse_map, os.path.join(MODEL_DIR, "label_mapping.pkl"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.pkl"))
    print(f"\n✅ Classes ({len(labels)}): {labels}")

    y = y_raw.map(label_map)

    # --- Clean ---
    X = X.apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    mask = ~X.isna().any(axis=1)
    X, y = X[mask], y[mask]
    X = X.astype(np.float32)

    # --- Scale ---
    # RobustScaler uses median and IQR — resistant to the extreme outliers
    # common in network traffic (e.g. huge src_bytes in exfiltration, DoS counts).
    # MinMaxScaler lets a single spike compress all benign values to near zero.
    scaler = RobustScaler(quantile_range=(10.0, 90.0))
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    print("✅ Scaler saved")

    # --- Split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"\n📊 Train: {len(X_train)} | Test: {len(X_test)}")

    # --- SMOTE for XGBoost only ---
    print("\n⚖️  SMOTE balancing for XGBoost...")
    sm = SMOTE(random_state=42, k_neighbors=3)
    X_train_bal, y_train_bal = sm.fit_resample(X_train, y_train)
    print(f"✅ Balanced train size: {len(X_train_bal)}")

    # --- Train XGBoost ---
    train_xgboost(
        X_train_bal, y_train_bal,
        X_test, y_test,
        num_classes=len(labels),
        label_names=labels
    )

    # --- Train Isolation Forest on full unbalanced scaled data ---
    train_isolation_forest(X_scaled)

    # --- Train Autoencoder on benign samples only ---
    benign_label_idx = label_map.get("Benign", None)
    if benign_label_idx is not None:
        benign_mask = (y == benign_label_idx).values
        X_benign = X_scaled[benign_mask]
        print(f"\n📌 Benign samples for autoencoder: {len(X_benign)}")
        train_autoencoder(X_benign, input_dim=X_scaled.shape[1])
    else:
        print("⚠️  No Benign class found — skipping autoencoder training.")

    print("\n🎉 TRAINING COMPLETE")
    print(f"📁 Models saved in: {MODEL_DIR}")
    print("\nSaved files:")
    for f in sorted(os.listdir(MODEL_DIR)):
        print(f"  ✅ {f}")


if __name__ == "__main__":
    main()