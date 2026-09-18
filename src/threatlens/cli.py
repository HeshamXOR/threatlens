"""Command-line interface: ``threatlens <url-or-file> ...``"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .url.detector import URLDetector


def _looks_like_url(target: str) -> bool:
    return "://" in target or "." in target and not Path(target).exists()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="Detect malicious URLs and Windows executables.",
    )
    parser.add_argument("targets", nargs="+", help="URLs and/or paths to PE files")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--threshold", type=float, default=0.5, help="decision threshold (default 0.5)")
    parser.add_argument("--version", action="version", version=f"threatlens {__version__}")
    args = parser.parse_args(argv)

    url_detector = None
    pe_detector = None
    results = []

    for target in args.targets:
        is_file = Path(target).exists() and Path(target).is_file()
        if is_file:
            if pe_detector is None:
                try:
                    from .files.detector import PEDetector
                    pe_detector = PEDetector()
                except ImportError:
                    print(
                        f"skip (needs 'files' extra): {target}\n"
                        "  install with: pip install threatlens[files]",
                        file=sys.stderr,
                    )
                    continue
            results.append(pe_detector.predict_file(target, threshold=args.threshold))
        else:
            if url_detector is None:
                url_detector = URLDetector()
            results.append(url_detector.predict(target, threshold=args.threshold))

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print(r)

    # Non-zero exit if anything was flagged malicious — handy in scripts/CI.
    return 1 if any(r.is_malicious for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
