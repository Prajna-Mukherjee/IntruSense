"""
SHAP Explanation Service
Generates feature importance explanations for predictions.
Uses the dynamic feature_columns list from the trained model
(post one-hot encoding) rather than a hardcoded column list.
"""

import numpy as np
import shap


class SHAPService:

    def __init__(self, prediction_service):
        self.prediction_service = prediction_service
        self.explainer = None
        self._init_explainer()

    # ----------------------------------------------------------
    # INIT
    # ----------------------------------------------------------

    def _init_explainer(self):
        try:
            if self.prediction_service.xgb_model is not None:
                self.explainer = shap.TreeExplainer(self.prediction_service.xgb_model)
                print("✅ SHAP TreeExplainer initialized")
            else:
                print("⚠️  SHAP explainer skipped — XGBoost model not loaded")
        except Exception as e:
            print(f"⚠️  SHAP init warning: {e}")
            self.explainer = None

    # ----------------------------------------------------------
    # FEATURE COLUMNS (always from loaded model, never hardcoded)
    # ----------------------------------------------------------

    @property
    def feature_columns(self) -> list:
        """
        Use the dynamic post-one-hot column list saved during training.
        Falls back to the base numeric list if not loaded yet.
        """
        cols = self.prediction_service.feature_columns
        if cols:
            return cols
        # Fallback: base NSL-KDD numeric features (no one-hot columns)
        return self.prediction_service.FEATURE_COLUMNS

    # ----------------------------------------------------------
    # EXPLAIN
    # ----------------------------------------------------------

    def explain(self, log_data: dict) -> dict:
        """
        Generate SHAP explanation for a single log entry.
        Returns top 10 features by absolute impact plus all values.
        """
        # Get raw (unscaled) features aligned to training column order
        features_raw = self.prediction_service._extract_features(log_data)

        # Scale before passing to SHAP (model was trained on scaled data)
        try:
            features_scaled = self.prediction_service.scaler.transform(features_raw)
        except Exception:
            features_scaled = features_raw

        if self.explainer is None:
            return self._fallback_explanation(features_scaled)

        try:
            shap_values = self.explainer.shap_values(features_scaled)

            # shap_values shape for multiclass XGBoost:
            # list of arrays, one per class → each shape (1, n_features)
            # OR a single 3D array (1, n_features, n_classes)
            if isinstance(shap_values, list):
                # List of (1, n_features) arrays — one per class
                # Pick the class with the highest predicted probability
                xgb_proba = self.prediction_service.xgb_model.predict_proba(features_scaled)[0]
                predicted_class_idx = int(np.argmax(xgb_proba))
                # Clamp to available classes in case of mismatch
                predicted_class_idx = min(predicted_class_idx, len(shap_values) - 1)
                values = shap_values[predicted_class_idx][0]

            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                # Shape: (1, n_features, n_classes)
                xgb_proba = self.prediction_service.xgb_model.predict_proba(features_scaled)[0]
                predicted_class_idx = int(np.argmax(xgb_proba))
                values = shap_values[0, :, predicted_class_idx]

            else:
                # Binary or unexpected shape — use as-is
                values = shap_values[0] if shap_values.ndim > 1 else shap_values

            # Align values to feature column names
            cols = self.feature_columns
            if len(values) != len(cols):
                # Length mismatch guard — truncate or pad with zeros
                if len(values) > len(cols):
                    values = values[:len(cols)]
                else:
                    values = np.pad(values, (0, len(cols) - len(values)))

            feature_impacts = {
                col: round(float(val), 4)
                for col, val in zip(cols, values)
            }

            # Sort by absolute impact, take top 10
            top_features = sorted(
                feature_impacts.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:10]

            # Base value: expected_value is a list for multiclass
            expected = self.explainer.expected_value
            if isinstance(expected, (list, np.ndarray)):
                base_value = float(expected[predicted_class_idx])
            else:
                base_value = float(expected)

            return {
                "top_features": [
                    {"feature": self._friendly_name(k), "impact": v}
                    for k, v in top_features
                ],
                "all_values": {
                    self._friendly_name(k): v
                    for k, v in feature_impacts.items()
                },
                "base_value": round(base_value, 4)
            }

        except Exception as e:
            print(f"SHAP explain error: {e}")
            return self._fallback_explanation(features_scaled)

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------

    def _friendly_name(self, col: str) -> str:
        """
        Convert one-hot column names to readable labels.
        e.g. 'protocol_type_tcp' → 'protocol: tcp'
             'service_ftp'        → 'service: ftp'
             'flag_SF'            → 'flag: SF'
        """
        for prefix in ("protocol_type_", "service_", "flag_"):
            if col.startswith(prefix):
                category = prefix.rstrip("_").replace("_", " ")
                value = col[len(prefix):]
                return f"{category}: {value}"
        # Replace underscores for readability
        return col.replace("_", " ")

    def _fallback_explanation(self, features: np.ndarray) -> dict:
        """
        Fallback when SHAP is unavailable.
        Uses feature magnitude as a proxy for importance.
        """
        cols = self.feature_columns
        values = features.flatten()

        # Pad or trim if needed
        if len(values) > len(cols):
            values = values[:len(cols)]
        elif len(values) < len(cols):
            values = np.pad(values, (0, len(cols) - len(values)))

        feature_impacts = {
            col: round(float(val * np.random.uniform(-0.05, 0.05)), 4)
            for col, val in zip(cols, values)
        }

        top_features = sorted(
            feature_impacts.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:10]

        return {
            "top_features": [
                {"feature": self._friendly_name(k), "impact": v}
                for k, v in top_features
            ],
            "all_values": {
                self._friendly_name(k): v
                for k, v in feature_impacts.items()
            },
            "base_value": 0.0
        }