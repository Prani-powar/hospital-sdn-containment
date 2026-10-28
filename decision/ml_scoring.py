"""Read-only scorer for trusted offline M1/M2 training artifacts.

Model files are Python joblib/pickle artefacts. Load only directories generated
locally by ``decision.ml_pipeline`` and kept under project control; never accept
an uploaded model through a web endpoint.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib

from decision.features import FEATURE_FIELDS
from decision.ml_pipeline import FEATURE_VERSION, MODEL_FIELDS, ROLES


class MlScorer:
    def __init__(self, m1: dict, m2, metadata: dict) -> None:
        self.m1, self.m2, self.metadata = m1, m2, metadata

    @classmethod
    def from_directory(cls, directory: Path) -> "MlScorer":
        directory = Path(directory)
        metadata = json.loads((directory / "metrics.json").read_text(encoding="utf-8"))
        if (not isinstance(metadata, dict) or metadata.get("schema_version") != 1 or
                metadata.get("feature_spec_version") != FEATURE_VERSION or
                metadata.get("model_fields") != list(MODEL_FIELDS)):
            raise ValueError("Unsupported ML artifact metadata")
        m1 = joblib.load(directory / "m1_isolation_forest.joblib")
        m2 = joblib.load(directory / "m2_random_forest.joblib")
        if (not isinstance(m1, dict) or m1.get("feature_spec_version") != FEATURE_VERSION or
                tuple(m1.get("model_fields", ())) != MODEL_FIELDS or not isinstance(m1.get("models"), dict) or
                not isinstance(m1.get("raw_score_thresholds"), dict)):
            raise ValueError("Unsupported M1 artifact")
        return cls(m1, m2, metadata)

    def score(self, feature: dict) -> dict:
        if not isinstance(feature, dict) or set(feature) != set(FEATURE_FIELDS):
            raise ValueError("Feature contract mismatch")
        role = feature.get("role")
        if role not in ROLES or role not in self.m1["models"]:
            raise ValueError("No M1 model for feature role")
        if not all(type(feature[key]) is int and feature[key] >= 0 for key in MODEL_FIELDS):
            raise ValueError("Invalid feature values")
        vector = [[feature[key] for key in MODEL_FIELDS]]
        raw = float(-self.m1["models"][role].decision_function(vector)[0])
        threshold = float(self.m1["raw_score_thresholds"][role])
        m2_probability = float(self.m2.predict_proba(vector)[0, 1])
        return {"model_artifact_created_at": self.metadata["created_at"], "role": role,
                "m1_raw_anomaly_score": raw, "m1_threshold": threshold,
                "m1_anomalous": raw >= threshold, "m2_attack_probability": m2_probability,
                "m2_threshold": float(self.metadata["models"]["m2_random_forest"]["threshold"]),
                "m2_anomalous": m2_probability >= float(self.metadata['models']['m2_random_forest']['threshold']),
                "policy_binding": "selected explicitly by decision.live --detector; scoring alone does not mutate"}
