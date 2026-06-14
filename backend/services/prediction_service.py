import numpy as np
import joblib
import os
from sklearn.preprocessing import RobustScaler

# =========================================================
# NSL-KDD raw feature names (before one-hot encoding)
# These are the fields expected in incoming log_data dicts.
# =========================================================

NSL_KDD_BASE_FEATURES = [
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
    "dst_host_srv_rerror_rate"
]

# Categorical columns that get one-hot encoded during training
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# Kept for SHAP feature name reference (non-categorical numerics)
FEATURE_COLUMNS = [c for c in NSL_KDD_BASE_FEATURES if c not in CATEGORICAL_COLS]

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

# =========================================================
# ALL KNOWN THREAT LABELS
# Covers NSL-KDD classes + synthetic modern attack classes.
# Anything not in this set and not "Benign" is treated as
# Anomalous Behavior (caught by IsolationForest/Autoencoder).
# =========================================================

THREAT_LABELS = {
    "DoS", "DDoS", "PortScan", "BruteForce", "Exploit",
    "C2", "LateralMovement", "Exfiltration", "WebAttack"
}


class PredictionService:

    def __init__(self):
        self.xgb_model = None
        self.isolation_forest = None
        self.autoencoder = None
        self.scaler = RobustScaler()
        self.label_mapping = {}       # {0: "Benign", 1: "BruteForce", ...}
        self.feature_columns = []     # exact column list after one-hot (from training)
        self._load_models()

    # ----------------------------------------------------------
    # MODEL LOADING
    # ----------------------------------------------------------

    def _load_models(self):
        try:
            self.xgb_model = joblib.load(os.path.join(MODEL_DIR, "xgboost_model.pkl"))
            self.isolation_forest = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
            self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
            self.label_mapping = joblib.load(os.path.join(MODEL_DIR, "label_mapping.pkl"))
            self.feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))

            try:
                from tensorflow.keras.models import load_model
                ae_path = os.path.join(MODEL_DIR, "autoencoder.h5")
                if os.path.exists(ae_path):
                    self.autoencoder = load_model(ae_path)
                    print("✅ Autoencoder loaded")
                else:
                    self.autoencoder = None
                    print("⚠️  autoencoder.h5 not found — using fallback AE score")
            except Exception as e:
                self.autoencoder = None
                print(f"⚠️  Autoencoder load warning: {e}")

            print("✅ Models loaded successfully")
            print(f"   Classes: {list(self.label_mapping.values())}")
            print(f"   Feature count: {len(self.feature_columns)}")

        except FileNotFoundError as e:
            print(f"❌ Model file not found: {e}")
            print("   Run: python scripts/train_models.py --data /path/to/nsl-kdd/")

    def models_loaded(self) -> bool:
        return self.xgb_model is not None and len(self.feature_columns) > 0

    # ----------------------------------------------------------
    # FEATURE EXTRACTION
    # Converts a raw log dict → aligned numpy array matching
    # the exact column order produced during training.
    # ----------------------------------------------------------

    def _extract_features(self, log_data: dict) -> np.ndarray:
        """
        1. One-hot encode categorical fields the same way pandas.get_dummies did.
        2. Fill every column in self.feature_columns (0 if missing).
        3. Return shape (1, n_features).
        """
        row = {}

        # Copy numeric fields directly
        for col in NSL_KDD_BASE_FEATURES:
            if col in CATEGORICAL_COLS:
                continue
            val = log_data.get(col, 0)
            try:
                row[col] = float(val)
            except (ValueError, TypeError):
                row[col] = 0.0

        # One-hot encode categoricals
        # pandas get_dummies produces columns like "protocol_type_tcp", "service_ftp", etc.
        for cat_col in CATEGORICAL_COLS:
            val = str(log_data.get(cat_col, "")).lower().strip()
            # Find all columns in feature_columns that belong to this categorical
            prefix = f"{cat_col}_"
            for fc in self.feature_columns:
                if fc.startswith(prefix):
                    category_value = fc[len(prefix):]  # e.g. "tcp", "udp", "icmp"
                    row[fc] = 1.0 if val == category_value else 0.0

        # Align to exact training column order, fill missing with 0
        aligned = np.array(
            [row.get(col, 0.0) for col in self.feature_columns],
            dtype=np.float32
        ).reshape(1, -1)

        return aligned

    # ----------------------------------------------------------
    # PREDICTION
    # ----------------------------------------------------------

    def predict(self, log_data: dict) -> dict:
        if not self.models_loaded():
            return {
                "is_threat": False,
                "attack_type": "Unknown",
                "threat_score": 0.0,
                "confidence": 0.0,
                "xgb_probability": 0.0,
                "isolation_forest_anomaly": False,
                "autoencoder_score": 0.0,
                "error": "Models not loaded"
            }

        features_raw = self._extract_features(log_data)
        features = self.scaler.transform(features_raw)

        # --- XGBoost ---
        xgb_proba = self.xgb_model.predict_proba(features)[0]
        xgb_class_idx = int(np.argmax(xgb_proba))
        xgb_confidence = float(xgb_proba[xgb_class_idx])
        attack_type = self.label_mapping.get(xgb_class_idx, "Unknown")

        # Threat probability = 1 - P(Benign)
        benign_idx = self._get_benign_idx()
        xgb_threat_prob = float(1.0 - xgb_proba[benign_idx]) if benign_idx is not None else float(xgb_proba[xgb_class_idx])

        # --- Isolation Forest ---
        if_score = float(self.isolation_forest.decision_function(features)[0])
        if_anomaly = self.isolation_forest.predict(features)[0] == -1
        # More negative score = more anomalous. Typical range is [-0.5, 0.5].
        # Normalize to [0,1]: use a tighter window to avoid over-flagging.
        if_normalized = float(max(0.0, min(1.0, (0.05 - if_score) / 0.4)))

        # --- Autoencoder ---
        ae_score = self._autoencoder_score(features)

        # --- Fusion ---
        # XGBoost is primary (0.60 weight). Anomaly detectors provide supporting
        # signals. Weighting: XGB 0.60, IF 0.25, AE 0.15.
        threat_score = (xgb_threat_prob * 0.60) + (if_normalized * 0.25) + (ae_score * 0.15)

        # --- Decision logic ---
        # XGBoost confident benign: raise the bar slightly from 0.6 → 0.65 to
        # avoid benign misclassification on borderline samples.
        xgb_confident_benign = (attack_type == "Benign" and xgb_confidence >= 0.65)

        if xgb_confident_benign:
            is_threat = False
            final_attack_type = "Benign"
        elif attack_type in THREAT_LABELS and xgb_confidence >= 0.45:
            # Require at least 0.45 confidence for a named threat label —
            # prevents low-confidence XGB guesses from being treated as firm detections.
            is_threat = True
            final_attack_type = attack_type
        elif attack_type in THREAT_LABELS and (if_anomaly or ae_score > 0.55):
            # XGB detected a threat class but with low confidence; anomaly detectors
            # agree → still flag, but use a softer label.
            is_threat = True
            final_attack_type = attack_type
        elif attack_type not in THREAT_LABELS and (if_anomaly and ae_score > 0.55):
            # XGB says benign but both anomaly detectors disagree strongly.
            is_threat = True
            final_attack_type = "Anomalous Behavior"
        else:
            is_threat = False
            final_attack_type = "Benign"

        return {
            "is_threat": bool(is_threat),
            "attack_type": final_attack_type,
            "threat_score": round(float(threat_score), 4),
            "confidence": round(xgb_confidence, 4),
            "xgb_probability": round(xgb_threat_prob, 4),
            "isolation_forest_anomaly": bool(if_anomaly),
            "autoencoder_score": round(ae_score, 4)
        }

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------

    def _get_benign_idx(self):
        """Return the integer index of the Benign class."""
        for idx, name in self.label_mapping.items():
            if name == "Benign":
                return idx
        return None

    def _autoencoder_score(self, features: np.ndarray) -> float:
        if self.autoencoder is not None:
            try:
                reconstructed = self.autoencoder.predict(features, verbose=0)
                error = float(np.mean((features - reconstructed) ** 2))
                # RobustScaler output is not bounded to [0,1] — MSE can be larger.
                # Empirical tuning: benign MSE typically < 0.5, attack MSE > 1.5.
                # Sigmoid-style normalization: saturates near 1.0 for high error.
                return float(min(1.0, error / 2.0))
            except Exception:
                pass
        # Fallback: variance-based proxy (unchanged)
        variance = float(np.var(features))
        return min(1.0, variance / 0.1)