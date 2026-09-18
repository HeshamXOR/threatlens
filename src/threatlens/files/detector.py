"""PE (Windows executable) malware detection via EMBER features + XGBoost."""

from __future__ import annotations

import time
import warnings
from pathlib import Path

import joblib
import numpy as np

from ..result import DetectionResult
from ..paths import pe_models_dir
from .ember_features import get_feature_extractor


class PEDetector:
    """
    Detect malicious Windows PE files (``.exe``/``.dll``/``.sys``).

    Parses the binary into 2381 EMBER 2018 v2 features (via LIEF) and scores it
    with a gradient-boosted classifier. Requires the ``files`` extra:
    ``pip install threatlens[files]``.

        >>> from threatlens import PEDetector
        >>> PEDetector().predict_file("sample.exe").verdict
        'benign'
    """

    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path) if model_path else pe_models_dir() / "xgb_malware_model.joblib"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._model = joblib.load(self.model_path)
        self._extractor = get_feature_extractor()

    def predict_bytes(self, data: bytes, threshold: float = 0.5) -> DetectionResult:
        """Score raw PE bytes."""
        start = time.perf_counter()
        features, sha256 = self._extractor.extract_with_hash(data)
        x = np.asarray(features, dtype=np.float32).reshape(1, -1)

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="X does not have valid feature names")
            score = float(self._model.predict_proba(x)[0, 1])

        verdict = "malicious" if score >= threshold else "benign"
        confidence = min(99.9, abs(score - 0.5) * 200)

        return DetectionResult(
            target=sha256,
            kind="pe",
            verdict=verdict,
            score=round(score, 6),
            confidence=round(confidence, 1),
            signals={},
            details={"sha256": sha256, "threshold": threshold, "ember_features": int(features.shape[0])},
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
        )

    def predict_file(self, path: str | Path, threshold: float = 0.5) -> DetectionResult:
        """Score a PE file on disk. The result's ``target`` is set to the path."""
        path = Path(path)
        with open(path, "rb") as fh:
            data = fh.read()
        result = self.predict_bytes(data, threshold=threshold)
        # Report the path as the target, keep the sha256 in details.
        object.__setattr__(result, "target", str(path))
        return result
