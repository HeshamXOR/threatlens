"""
URL feature engineering — 66 lexical features for malicious-URL detection.

Features are grouped into nine categories (length, character counts, ratios,
entropy, boolean indicators, domain/TLD signals, suspicious-pattern scores,
path/query analysis, and advanced lexical features). The column order in
``FEATURE_NAMES`` is the exact order the scaler and models expect — do not
reorder it.

``tldextract`` is optional: when it is installed the domain/subdomain/TLD split
is more accurate, and there is a hostname-based fallback when it is not.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

import numpy as np

try:
    import tldextract
except ImportError:
    tldextract = None

# ── Regex patterns (compiled once) ────────────────────────────────────────────
_IP_RE = re.compile(r"(?:^|[/@])(\d{1,3}\.){3}\d{1,3}(?:[:/]|$)")
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SHORTENERS = frozenset([
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly",
    "shorturl.at", "rebrand.ly",
])
_SUSPICIOUS_TLDS = frozenset([
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc",
    "club", "work", "date", "racing", "stream", "download",
    "win", "bid", "icu", "buzz", "monster",
])
_SUSPICIOUS_EXT = re.compile(
    r"\.(exe|zip|rar|scr|bat|cmd|js|vbs|ps1|dll|msi|apk|dmg|iso|php|cgi)(\?|$)",
    re.IGNORECASE,
)
_PHISHING_KW = re.compile(
    r"(login|signin|verify|account|update|secure|bank|confirm|password|"
    r"credential|suspend|alert|notification|wallet|paypal|apple|microsoft|"
    r"amazon|netflix|facebook|instagram|whatsapp|dropbox|google|icloud)",
    re.IGNORECASE,
)
_BRAND_NAMES = [
    "google", "facebook", "apple", "amazon", "microsoft", "netflix",
    "paypal", "instagram", "whatsapp", "dropbox", "linkedin", "twitter",
    "yahoo", "ebay", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "dhl", "fedex", "usps",
]

# Feature names in the exact order the scaler/models expect.
FEATURE_NAMES = [
    # 1. Length
    "url_length", "hostname_length", "domain_length", "path_length",
    "query_length", "fragment_length", "tld_length",
    # 2. Counts
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_at_signs", "num_ampersands", "num_equals", "num_question_marks",
    "num_percent", "num_tilde", "num_digits", "num_letters",
    "num_special", "num_params",
    # 3. Ratios
    "digit_ratio", "letter_ratio", "special_ratio", "uppercase_ratio",
    "digit_letter_ratio",
    # 4. Entropy
    "url_entropy", "domain_entropy",
    # 5. Booleans
    "has_ip", "has_https", "has_http", "has_www", "has_port",
    "has_at_symbol", "is_shortened", "has_double_slash_redirect",
    "has_punycode", "has_hex_encoding",
    # 6. Domain
    "num_subdomains", "subdomain_length", "domain_token_count",
    "has_suspicious_tld", "domain_has_digits", "domain_hyphen_count",
    # 7. Suspicious
    "phishing_keyword_count", "brand_count", "has_suspicious_ext",
    "brand_in_subdomain", "suspicious_word_ratio",
    # 8. Path / query
    "path_depth", "longest_path_token", "avg_path_token_len",
    "max_consecutive_digits", "path_entropy",
    # 9. Advanced lexical
    "consonant_sequence_max", "vowel_ratio", "bigram_frequency_score",
    "leetspeak_score", "homoglyph_count", "brand_edit_distance",
    "redirect_chain_score", "path_randomness_score", "tld_rank",
    "url_depth_ratio", "repeated_char_ratio", "query_entropy",
]

_CONSONANTS_RE = re.compile(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+")
_COMMON_BIGRAMS = frozenset([
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "es",
    "ti", "te", "or", "st", "ar", "nd", "to", "nt", "is", "of",
])
_HOMOGLYPHS = set("аеіорсухаеіорсух")


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    cnt = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in cnt.values())


def extract_features(url: str) -> np.ndarray:
    """Extract 66 lexical features as a float32 array of shape (66,)."""
    try:
        features = _extract_features_inner(url)
    except Exception:
        features = {name: 0 for name in FEATURE_NAMES}
    return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float32)


def extract_features_dict(url: str) -> dict:
    """Extract the 66 features as a name -> value dict."""
    try:
        return _extract_features_inner(url)
    except Exception:
        return {name: 0 for name in FEATURE_NAMES}


def _extract_features_inner(url: str) -> dict:
    url = str(url).strip()

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        try:
            safe = url.replace("[", "").replace("]", "")
            parsed = urlparse(safe if "://" in safe else f"http://{safe}")
        except Exception:
            parsed = urlparse("http://invalid")

    try:
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    scheme = (parsed.scheme or "").lower()

    if tldextract is not None:
        ext = tldextract.extract(url)
        domain = ext.domain
        tld = ext.suffix
        subdomain = ext.subdomain
    else:
        domain = hostname.split(".")[-2] if hostname.count(".") >= 1 else hostname
        tld = hostname.split(".")[-1] if "." in hostname else ""
        subdomain = ".".join(hostname.split(".")[:-2]) if hostname.count(".") >= 2 else ""

    url_lower = url.lower()

    # 1. Length / structural
    url_length = len(url)
    hostname_length = len(hostname)
    domain_length = len(domain)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)
    tld_length = len(tld)

    # 2. Character counts
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_at_signs = url.count("@")
    num_ampersands = url.count("&")
    num_equals = url.count("=")
    num_question_marks = url.count("?")
    num_percent = url.count("%")
    num_tilde = url.count("~")
    num_digits = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)
    num_special = sum(not c.isalnum() and c not in ":/." for c in url)
    num_params = len(parse_qs(query))

    # 3. Character ratios
    safe_len = max(url_length, 1)
    digit_ratio = num_digits / safe_len
    letter_ratio = num_letters / safe_len
    special_ratio = num_special / safe_len
    uppercase_ratio = sum(c.isupper() for c in url) / safe_len
    digit_letter_ratio = num_digits / max(num_letters, 1)

    # 4. Entropy
    url_entropy = _entropy(url)
    domain_entropy = _entropy(hostname)

    # 5. Boolean indicators
    has_ip = int(bool(_IP_RE.search(url)))
    has_https = int(scheme == "https")
    has_http = int(scheme == "http")
    has_www = int("www." in url_lower)
    try:
        _port = parsed.port
    except (ValueError, TypeError):
        _port = None
    has_port = int(_port is not None and _port not in (80, 443))
    has_at_symbol = int("@" in url)
    is_shortened = 1 if any(s == hostname or hostname.endswith("." + s) for s in _SHORTENERS) else 0
    has_double_slash_redirect = int("//" in path)
    has_punycode = int("xn--" in url_lower)
    has_hex_encoding = int(bool(_HEX_RE.search(url)))

    # 6. Domain / TLD signals
    num_subdomains = subdomain.count(".") + 1 if subdomain else 0
    subdomain_length = len(subdomain)
    domain_token_count = len(re.split(r"[.\-_]", hostname))
    has_suspicious_tld = int(tld.lower() in _SUSPICIOUS_TLDS)
    domain_has_digits = int(any(c.isdigit() for c in domain))
    domain_hyphen_count = domain.count("-")

    # 7. Suspicious-pattern scores
    phishing_keyword_count = len(_PHISHING_KW.findall(url_lower))
    brand_count = sum(1 for b in _BRAND_NAMES if b in url_lower)
    has_suspicious_ext = int(bool(_SUSPICIOUS_EXT.search(url_lower)))
    brand_in_subdomain = int(
        any(b in subdomain.lower() for b in _BRAND_NAMES)
        and not any(b in domain.lower() for b in _BRAND_NAMES)
    ) if subdomain else 0
    suspicious_word_ratio = phishing_keyword_count / max(
        len(re.findall(r"[a-zA-Z]+", url)), 1
    )

    # 8. Path & query analysis
    path_tokens = [t for t in path.split("/") if t]
    path_depth = len(path_tokens)
    longest_path_token = max((len(t) for t in path_tokens), default=0)
    avg_path_token_len = (
        sum(len(t) for t in path_tokens) / len(path_tokens) if path_tokens else 0.0
    )
    max_consecutive_digits = max(
        (len(m.group()) for m in re.finditer(r"\d+", url)), default=0
    )
    path_entropy = _entropy(path)

    # 9. Advanced lexical features
    consonants = _CONSONANTS_RE.findall(domain)
    consonant_sequence_max = max(len(c) for c in consonants) if consonants else 0

    vowels_count = sum(1 for c in domain if c in "aeiouAEIOU")
    vowel_ratio = vowels_count / max(len(domain), 1)

    domain_lower = domain.lower()
    bigrams = [domain_lower[i:i + 2] for i in range(len(domain_lower) - 1)]
    bigram_frequency_score = sum(1 for b in bigrams if b in _COMMON_BIGRAMS) / max(len(bigrams), 1)

    leetspeak_chars = set("0134578")
    leetspeak_score = sum(1 for c in domain if c in leetspeak_chars)

    homoglyph_count = sum(1 for c in url if c in _HOMOGLYPHS)

    if not domain_lower:
        brand_edit_distance = 999.0
    else:
        brand_distances = []
        for b in _BRAND_NAMES:
            if b in domain_lower:
                brand_distances.append(0)
            else:
                brand_distances.append(_levenshtein(domain_lower, b))
        brand_edit_distance = float(min(brand_distances)) if brand_distances else 999.0

    redirect_chain_score = max(0, url_lower.count("http://") + url_lower.count("https://") - 1)
    if "://" in url_lower:
        rest = url_lower.split("://", 1)[1]
        if "http" in rest or "www" in rest or "@" in rest:
            redirect_chain_score += 1

    segments = [s for s in path.split("/") if s]
    path_randomness_score = max((_entropy(s) for s in segments), default=0.0)

    tld_lower = tld.lower()
    if tld_lower in ("com", "org", "net", "edu", "gov"):
        tld_rank = 0.0
    elif tld_lower in ("uk", "jp", "de", "fr", "co", "io", "app", "dev"):
        tld_rank = 1.0
    elif tld_lower in _SUSPICIOUS_TLDS:
        tld_rank = 3.0
    else:
        tld_rank = 2.0

    url_depth_ratio = path_depth / max(url_length, 1)

    if domain:
        char_counts = Counter(domain)
        most_common_cnt = char_counts.most_common(1)[0][1]
        repeated_char_ratio = most_common_cnt / len(domain)
    else:
        repeated_char_ratio = 0.0

    query_entropy = _entropy(query)

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "tld_length": tld_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_at_signs": num_at_signs,
        "num_ampersands": num_ampersands,
        "num_equals": num_equals,
        "num_question_marks": num_question_marks,
        "num_percent": num_percent,
        "num_tilde": num_tilde,
        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_special": num_special,
        "num_params": num_params,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "special_ratio": special_ratio,
        "uppercase_ratio": uppercase_ratio,
        "digit_letter_ratio": digit_letter_ratio,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "has_ip": has_ip,
        "has_https": has_https,
        "has_http": has_http,
        "has_www": has_www,
        "has_port": has_port,
        "has_at_symbol": has_at_symbol,
        "is_shortened": is_shortened,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_punycode": has_punycode,
        "has_hex_encoding": has_hex_encoding,
        "num_subdomains": num_subdomains,
        "subdomain_length": subdomain_length,
        "domain_token_count": domain_token_count,
        "has_suspicious_tld": has_suspicious_tld,
        "domain_has_digits": domain_has_digits,
        "domain_hyphen_count": domain_hyphen_count,
        "phishing_keyword_count": phishing_keyword_count,
        "brand_count": brand_count,
        "has_suspicious_ext": has_suspicious_ext,
        "brand_in_subdomain": brand_in_subdomain,
        "suspicious_word_ratio": suspicious_word_ratio,
        "path_depth": path_depth,
        "longest_path_token": longest_path_token,
        "avg_path_token_len": avg_path_token_len,
        "max_consecutive_digits": max_consecutive_digits,
        "path_entropy": path_entropy,
        "consonant_sequence_max": consonant_sequence_max,
        "vowel_ratio": vowel_ratio,
        "bigram_frequency_score": bigram_frequency_score,
        "leetspeak_score": leetspeak_score,
        "homoglyph_count": homoglyph_count,
        "brand_edit_distance": brand_edit_distance,
        "redirect_chain_score": redirect_chain_score,
        "path_randomness_score": path_randomness_score,
        "tld_rank": tld_rank,
        "url_depth_ratio": url_depth_ratio,
        "repeated_char_ratio": repeated_char_ratio,
        "query_entropy": query_entropy,
    }
