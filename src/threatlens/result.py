"""Shared detection result type."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class DetectionResult:
    """
    The outcome of a single detection.

    Attributes:
        target: What was analysed — the URL string or the file path.
        kind: ``"url"`` or ``"pe"``.
        verdict: ``"malicious"`` or ``"benign"``.
        score: Calibrated probability of maliciousness, in [0, 1].
        confidence: How far the score sits from the 0.5 boundary, as a
            percentage in [0, 99.9]. High confidence means a decisive score,
            not a more accurate one.
        signals: The notable feature values that informed the verdict
            (name -> value). Empty when nothing stood out.
        details: Model-specific extras (base-model scores, sha256, etc.).
        elapsed_ms: Wall-clock inference time in milliseconds.
    """

    target: str
    kind: str
    verdict: str
    score: float
    confidence: float
    signals: dict[str, float] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def is_malicious(self) -> bool:
        return self.verdict == "malicious"

    @property
    def confidence_level(self) -> str:
        """Coarse band: 'high' (>=80), 'medium' (>=50), else 'low'."""
        if self.confidence >= 80:
            return "high"
        if self.confidence >= 50:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"{self.verdict.upper()} ({self.score:.1%}, "
            f"{self.confidence_level} confidence) — {self.target}"
        )
