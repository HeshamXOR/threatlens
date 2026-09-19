<p align="center">
  <img src="https://raw.githubusercontent.com/HeshamXOR/threatlens/main/assets/logo.png" alt="threatlens" width="440">
</p>

<p align="center">
  <strong>Detect malicious URLs and Windows executables from Python</strong><br>
  Calibrated ML models that ship inside the package — no API keys, no network calls at inference time.
</p>

<p align="center">
  <a href="https://pypi.org/project/threatlens-ml/"><img src="https://img.shields.io/pypi/v/threatlens-ml?color=FA5F02&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/threatlens-ml/"><img src="https://img.shields.io/pypi/pyversions/threatlens-ml?color=FA5F02" alt="Python versions"></a>
  <a href="https://github.com/HeshamXOR/threatlens/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-FA5F02" alt="License"></a>
  <img src="https://img.shields.io/badge/models-bundled-30D158" alt="Models bundled">
</p>

---

```python
from threatlens import URLDetector

detector = URLDetector()
result = detector.predict("https://secure-paypal-login.xyz/verify-account")

print(result.verdict)      # 'malicious'
print(result.score)        # 0.99...
print(result.confidence)   # 99.9
print(result.signals)      # {'has_suspicious_tld': 1, 'phishing_keyword_count': 5, ...}
```

## Install

```bash
pip install threatlens-ml              # URL detection
pip install "threatlens-ml[files]"     # + Windows executable (PE) detection
```

> The PyPI package is **`threatlens-ml`** (the plain name was taken by an unrelated
> project), but you still **`import threatlens`** in code.

URL detection is the default and has light dependencies. Executable detection adds
[LIEF](https://lief.re/) for binary parsing, so it lives behind the `files` extra.

## Why another detector

Most lexical URL classifiers are trained on corpora that quietly label popular domains
as malicious, so they "detect" `github.com` as a threat and score everything at a flat
100%. threatlens was rebuilt specifically to fix that:

- the training corpus was **decontaminated** (mislabelled trusted-domain rows removed,
  verified benign URLs injected),
- the stacked score is **isotonically calibrated**, so probabilities are honest instead
  of pinned to 0 or 1,
- and a **trusted-domain safety net** dampens residual edge cases.

The result: `github.com` scores **0.4%**, `google.com` **0.02%**, and obvious phishing
still scores **~100%**.

## What it does

### URLs

A calibrated stacking ensemble scores a URL from **66 lexical features** — length,
entropy, character distribution, suspicious TLDs, brand-in-subdomain tricks, punycode
homoglyphs, shorteners, and more:

```
             ┌─ XGBoost ────────┐
 66 features ┤                  │
             └─ LightGBM ───────┤
                                ├─→ Logistic Regression ─→ isotonic ─→ score
 raw URL text ─ TF-IDF + LR ────┘      meta-learner        calibration
```

The three base models each estimate `P(malicious)`; a logistic meta-learner stacks them;
isotonic regression calibrates the result into a usable probability.

### Executables

Windows PE files (`.exe` / `.dll` / `.sys`) are parsed into **2381
[EMBER 2018 v2](https://github.com/elastic/ember) features** via LIEF and scored by a
gradient-boosted classifier.

```python
from threatlens import PEDetector          # pip install "threatlens-ml[files]"

pe = PEDetector()
print(pe.predict_file("sample.exe"))        # BENIGN (2.1%, high confidence) — sample.exe
```

## Command line

```bash
threatlens https://github.com https://secure-paypal-login.xyz/verify
threatlens suspicious.exe --json
threatlens https://example.com --threshold 0.3
```

```console
$ threatlens https://github.com "https://appleid-verify.ml/signin"
BENIGN (0.4%, high confidence) — https://github.com
MALICIOUS (99.8%, high confidence) — https://appleid-verify.ml/signin
```

The exit code is `1` if anything was flagged malicious, `0` otherwise — convenient in CI
and shell pipelines.

## The result object

Every call returns a `DetectionResult`:

| field | meaning |
|---|---|
| `target` | the URL, or the file path / sha256 |
| `kind` | `"url"` or `"pe"` |
| `verdict` | `"malicious"` or `"benign"` |
| `score` | calibrated probability of maliciousness, 0–1 |
| `confidence` | distance from the decision boundary, 0–99.9 |
| `signals` | notable feature values behind the verdict |
| `details` | per-model scores, sha256, threshold, raw (pre-calibration) score |
| `elapsed_ms` | inference time |

Plus `result.is_malicious`, `result.confidence_level` (`"high"` / `"medium"` / `"low"`),
and `result.to_dict()` for JSON serialization.

```python
r = detector.predict("http://192.168.1.50/login.php?bank=chase")
if r.is_malicious and r.confidence_level == "high":
    block(r.target)
```

## Batch scanning

The detector loads its models once at construction; reuse the instance across calls.

```python
detector = URLDetector()
flagged = [u for u in urls if detector.predict(u).is_malicious]
```

## Custom models

Point a detector at your own trained artifacts instead of the bundled ones:

```python
URLDetector(models_dir="path/to/url_models")
PEDetector(model_path="path/to/xgb.joblib")
```

The URL directory must contain `scaler`, `xgb_binary`, `lgbm_binary`, `tfidf_lr_binary`,
`hypermodel_meta`, and `hypermodel_calibrator` `.joblib` files; the meta-learner must take
3 inputs (the constructor verifies this and fails loudly on a mismatch).

You can also disable the trusted-domain safety net to see the raw model opinion:

```python
URLDetector(use_trusted_domains=False)
```

## Accuracy & honest limitations

| model | test set | accuracy | AUC |
|---|---|---|---|
| URL ensemble | 240,000 held-out URLs | 97.89% | 0.998 |
| PE classifier | EMBER 2018 v2 test set | 97.59% | — |

These are **static / lexical** detectors: they read structure and text, not runtime
behaviour. Treat a verdict as a strong signal, not proof, and keep a human in the loop for
consequential decisions. The trusted-domain list is a pragmatic backstop, not a substitute
for judgement — a genuinely compromised page on a trusted domain will be under-scored.

## Development

```bash
git clone https://github.com/HeshamXOR/threatlens
cd threatlens
pip install -e ".[dev]"
pytest
```

## License & attribution

Apache-2.0. Extracted from the
[MalwareGuard](https://github.com/HeshamXOR/MalwareGuard) project. PE feature extraction is
ported from [elastic/ember](https://github.com/elastic/ember) (MIT). Full attributions in
[`NOTICE`](https://github.com/HeshamXOR/threatlens/blob/main/NOTICE).
