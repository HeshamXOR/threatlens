"""Tests for the DetectionResult value type."""

from threatlens import DetectionResult


def _make(score, confidence, verdict="benign"):
    return DetectionResult(
        target="x", kind="url", verdict=verdict, score=score, confidence=confidence,
    )


def test_is_malicious():
    assert _make(0.9, 90, "malicious").is_malicious is True
    assert _make(0.1, 80, "benign").is_malicious is False


def test_confidence_levels():
    assert _make(0.99, 98).confidence_level == "high"
    assert _make(0.7, 60).confidence_level == "medium"
    assert _make(0.52, 4).confidence_level == "low"


def test_to_dict_roundtrip():
    d = _make(0.42, 16).to_dict()
    assert d["score"] == 0.42
    assert d["kind"] == "url"
    assert "signals" in d and "details" in d


def test_str_is_human_readable():
    s = str(_make(0.977, 95, "malicious"))
    assert "MALICIOUS" in s and "%" in s
