"""
threatlens — detect malicious URLs and Windows executables.

Two detectors, one small API:

    from threatlens import URLDetector
    det = URLDetector()
    result = det.predict("https://secure-paypal-login.xyz/verify-account")
    print(result.verdict, result.score)   # 'malicious' 0.99...

    from threatlens import PEDetector          # needs: pip install threatlens[files]
    PEDetector().predict_file("sample.exe")

Both return a :class:`DetectionResult`. Models ship bundled with the package,
so no download or network access is needed at runtime.
"""

from __future__ import annotations

from .result import DetectionResult
from .url.detector import URLDetector

__all__ = ["URLDetector", "PEDetector", "DetectionResult", "__version__"]

__version__ = "0.1.0"


def __getattr__(name: str):
    # PEDetector needs LIEF, an optional extra. Import lazily so that
    # `from threatlens import URLDetector` works without the files extra
    # installed, and surface a clear message if PEDetector is used without it.
    if name == "PEDetector":
        try:
            from .files.detector import PEDetector
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "PEDetector requires the 'files' extra. "
                "Install it with:  pip install threatlens[files]"
            ) from exc
        return PEDetector
    raise AttributeError(f"module 'threatlens' has no attribute {name!r}")
