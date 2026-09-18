"""URL malicious-detection: calibrated 3-model stacking ensemble."""

from __future__ import annotations

import time
import warnings
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np

from ..result import DetectionResult
from ..paths import url_models_dir
from .features import extract_features, extract_features_dict

# Popular domains trusted as a final safety net against false positives on
# major/official sites (e.g. OAuth consent URLs). The score is dampened, not
# hard-capped, so a genuinely compromised page on these domains can still flag.
TRUSTED_DOMAINS = {
    "google.com", "wikipedia.org", "wikimedia.org", "github.com", "github.io",
    "apple.com", "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
    "office.com", "bing.com", "msn.com", "yahoo.com", "amazon.com",
    "paypal.com", "wellsfargo.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "linkedin.com", "netflix.com", "dropbox.com", "zoom.us",
    "salesforce.com", "adobe.com", "ebay.com", "chase.com", "bankofamerica.com",
    "citibank.com", "hsbc.com", "dhl.com", "fedex.com", "usps.com", "spotify.com",
    "reddit.com", "google.co.uk", "google.ca", "google.de", "google.fr",
    "amazon.co.uk", "amazon.de", "amazon.co.jp",
}

_IMPORTANT_SIGNALS = [
    "has_ip", "has_suspicious_tld", "phishing_keyword_count",
    "brand_in_subdomain", "has_punycode", "is_shortened",
    "url_length", "num_subdomains", "has_https", "domain_entropy",
    "has_suspicious_ext", "has_hex_encoding", "brand_count",
    "path_depth", "url_entropy",
]


def _registered_domain(url: str) -> str:
    try:
        import tldextract
    except ImportError:
        tldextract = None

    url = str(url).strip()
    if "://" not in url:
        url = f"http://{url}"
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except Exception:
        hostname = ""
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    if tldextract is not None:
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            pass
    parts = hostname.split(".")
    return f"{parts[-2]}.{parts[-1]}".lower() if len(parts) >= 2 else hostname


class URLDetector:
    """
    Detect malicious URLs with a calibrated stacking ensemble.

    Loads all model artifacts once at construction (thread-safe for concurrent
    ``predict`` calls). Pass ``models_dir`` to use your own trained artifacts;
    by default the bundled models ship with the package.

        >>> from threatlens import URLDetector
        >>> URLDetector().predict("https://secure-paypal-login.xyz/verify").verdict
        'malicious'
    """

    BASE_MODEL_NAMES = ("XGBoost", "LightGBM", "TF-IDF + LR")

    def __init__(self, models_dir: str | Path | None = None, *, use_trusted_domains: bool = True):
        self.models_dir = Path(models_dir) if models_dir else url_models_dir()
        self.use_trusted_domains = use_trusted_domains
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._scaler = joblib.load(self.models_dir / "scaler.joblib")
            self._meta = joblib.load(self.models_dir / "hypermodel_meta.joblib")
            self._calibrator = joblib.load(self.models_dir / "hypermodel_calibrator.joblib")
            self._xgb = joblib.load(self.models_dir / "xgb_binary.joblib")
            self._lgbm = joblib.load(self.models_dir / "lgbm_binary.joblib")
            self._tfidf_lr = joblib.load(self.models_dir / "tfidf_lr_binary.joblib")

        n_meta = getattr(self._meta, "n_features_in_", None)
        if n_meta is not None and n_meta != len(self.BASE_MODEL_NAMES):
            raise ValueError(
                f"Meta-learner expects {n_meta} inputs but this detector stacks "
                f"{len(self.BASE_MODEL_NAMES)} base models. The artifacts in "
                f"{self.models_dir} do not match the expected ensemble topology."
            )

    def predict(self, url: str, threshold: float = 0.5) -> DetectionResult:
        """Score a single URL. Returns a :class:`DetectionResult`."""
        start = time.perf_counter()

        features = extract_features(url)[: self._scaler.n_features_in_].reshape(1, -1)
        x_scaled = self._scaler.transform(features).astype(np.float32)

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="X does not have valid feature names")
            p_xgb = float(self._xgb.predict_proba(x_scaled)[0, 1])
            p_lgbm = float(self._lgbm.predict_proba(x_scaled)[0, 1])
        p_tfidf = float(self._tfidf_lr.predict_proba([str(url)])[0, 1])

        meta_features = np.array([[p_xgb, p_lgbm, p_tfidf]], dtype=np.float32)
        raw_score = float(self._meta.predict_proba(meta_features)[0, 1])
        score = float(self._calibrator.predict([raw_score])[0])

        trusted = False
        if self.use_trusted_domains:
            reg = _registered_domain(url)
            if reg and reg in TRUSTED_DOMAINS:
                score *= 0.15
                trusted = True

        verdict = "malicious" if score > threshold else "benign"
        # Isotonic calibration can emit exactly 0.0/1.0; a flat 100% overstates
        # certainty, so the reported confidence is capped at 99.9.
        confidence = min(99.9, abs(score - 0.5) * 200)

        feats = extract_features_dict(url)
        signals = {
            f: round(float(feats[f]), 4)
            for f in _IMPORTANT_SIGNALS
            if f in feats and feats[f] != 0
        }

        return DetectionResult(
            target=url,
            kind="url",
            verdict=verdict,
            score=round(score, 6),
            confidence=round(confidence, 1),
            signals=signals,
            details={
                "raw_score": round(raw_score, 6),
                "base_model_scores": {
                    "XGBoost": round(p_xgb, 6),
                    "LightGBM": round(p_lgbm, 6),
                    "TF-IDF + LR": round(p_tfidf, 6),
                },
                "trusted_domain": trusted,
                "threshold": threshold,
            },
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
        )
