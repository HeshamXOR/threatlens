"""
Minimal threatlens usage.

    python examples/basic_usage.py
"""

from threatlens import URLDetector

detector = URLDetector()

urls = [
    "https://github.com",
    "https://www.google.com",
    "https://secure-paypal-login.xyz/verify-account",
    "http://192.168.1.50/login.php?bank=chase",
]

for url in urls:
    result = detector.predict(url)
    print(f"{result.verdict.upper():10} {result.score:6.1%}  {url}")
    if result.signals:
        top = ", ".join(f"{k}={v}" for k, v in list(result.signals.items())[:4])
        print(f"           signals: {top}")

# Scoring a PE file (requires: pip install threatlens[files])
#
#   from threatlens import PEDetector
#   pe = PEDetector()
#   print(pe.predict_file("sample.exe"))
