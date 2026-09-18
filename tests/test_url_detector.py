"""Behavioural tests for the URL detector.

These lock in the properties that motivated the model rebuild: popular domains
must not be flagged, obvious phishing must be, and the ensemble plumbing must
stay wired to a 3-column meta-learner. If a retrain regresses any of these,
these fail before anything ships.
"""

import pytest

from threatlens import URLDetector, DetectionResult
from threatlens.url import extract_features, FEATURE_NAMES


@pytest.fixture(scope="module")
def detector():
    return URLDetector()


def test_feature_vector_shape():
    vec = extract_features("https://example.com/path?q=1")
    assert vec.shape == (len(FEATURE_NAMES),) == (66,)
    assert vec.dtype.name == "float32"


def test_result_shape(detector):
    r = detector.predict("https://github.com")
    assert isinstance(r, DetectionResult)
    assert r.kind == "url"
    assert r.verdict in ("malicious", "benign")
    assert 0.0 <= r.score <= 1.0
    assert 0.0 <= r.confidence <= 99.9
    assert set(r.details["base_model_scores"]) == {"XGBoost", "LightGBM", "TF-IDF + LR"}


@pytest.mark.parametrize("url", [
    "https://github.com",
    "https://www.google.com",
    "https://en.wikipedia.org/wiki/Malware",
])
def test_popular_domains_are_benign(detector, url):
    # The regression this whole model rebuild existed to fix.
    r = detector.predict(url)
    assert r.verdict == "benign", f"{url} scored {r.score}"


@pytest.mark.parametrize("url", [
    "https://secure-paypal-login.xyz/verify-account",
    "http://appleid-verify.ml/signin",
])
def test_obvious_phishing_is_malicious(detector, url):
    r = detector.predict(url)
    assert r.verdict == "malicious", f"{url} scored {r.score}"


def test_confidence_never_claims_certainty(detector):
    # Isotonic calibration can emit exactly 1.0; the reported confidence caps at 99.9.
    r = detector.predict("https://secure-paypal-login.xyz/verify-account")
    assert r.confidence <= 99.9


def test_trusted_domain_dampening_can_be_disabled():
    plain = URLDetector(use_trusted_domains=False)
    r = plain.predict("https://github.com")
    assert r.details["trusted_domain"] is False


def test_malformed_input_does_not_crash(detector):
    for junk in ["", "not a url", "http://", "@@@", "https://[::1]"]:
        r = detector.predict(junk)
        assert r.verdict in ("malicious", "benign")
