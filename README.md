# threatlens

Detect malicious **URLs** and **Windows executables** from Python, with calibrated
machine-learning models that ship inside the package. No API keys, no network calls
at inference time.

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
pip install threatlens              # URL detection
pip install "threatlens[files]"     # + Windows executable (PE) detection
```

URL detection is the default and has light dependencies. Executable detection adds
[LIEF](https://lief.re/) for binary parsing, so it lives behind the `files` extra.

## What it does

### URLs

A calibrated stacking ensemble scores a URL from 66 lexical features (length, entropy,
character distribution, suspicious TLDs, brand-in-subdomain tricks, punycode, and more):

- **XGBoost** and **LightGBM** over the engineered features
- **TF-IDF + Logistic Regression** over the raw URL text
- a **Logistic Regression meta-learner** stacks those three
- **isotonic calibration** turns the stacked score into an honest probability
- a **trusted-domain safety net** dampens residual false positives on major sites

Calibration is what stops scores pinning to a flat 100%, and the cleaned training corpus
is what stopped the model calling `github.com` and `google.com` malicious.

### Executables

Windows PE files are parsed into 2381 [EMBER 2018 v2](https://github.com/elastic/ember)
features and scored by a gradient-boosted classifier.

```python
from threatlens import PEDetector          # pip install "threatlens[files]"

pe = PEDetector()
print(pe.predict_file("sample.exe"))        # BENIGN (2.1%, high confidence) — sample.exe
```

## Command line

```bash
threatlens https://github.com https://secure-paypal-login.xyz/verify
threatlens suspicious.exe --json
```

Exit code is `1` if anything was flagged malicious, `0` otherwise — convenient in CI.

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
| `details` | per-model scores, sha256, threshold |
| `elapsed_ms` | inference time |

`result.is_malicious`, `result.confidence_level` (`"high"`/`"medium"`/`"low"`) and
`result.to_dict()` are also available.

## Custom models

Point a detector at your own trained artifacts:

```python
URLDetector(models_dir="path/to/url_models")
PEDetector(model_path="path/to/xgb.joblib")
```

The URL directory must contain `scaler`, `xgb_binary`, `lgbm_binary`, `tfidf_lr_binary`,
`hypermodel_meta`, and `hypermodel_calibrator` `.joblib` files; the meta-learner must take
3 inputs (the constructor checks this and fails loudly otherwise).

## Accuracy & honesty

On held-out test sets: **97.89%** on 240,000 URLs (0.998 ROC-AUC) and **97.59%** on the
EMBER PE test set. These are lexical/static detectors — they read structure and text, not
runtime behaviour — so treat a verdict as a strong signal, not proof, and keep a human in
the loop for consequential decisions. The bundled trusted-domain list is a pragmatic
backstop, not a substitute for judgement.

## License

Apache-2.0. Carved out of the [MalwareGuard](https://github.com/HeshamXOR/MalwareGuard)
project. PE feature extraction is ported from [elastic/ember](https://github.com/elastic/ember)
(MIT). See `NOTICE` for attributions.
