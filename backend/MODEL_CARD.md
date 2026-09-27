# Anti-Phishing ML Model Card

## Model Details
- **Name:** Anti-Phishing XGBoost Classifier
- **Version:** v2.0 (Candidate / Shadow Mode) - 16-feature schema
- **Current Production Version:** v1.0 - 9-feature schema
- **Architecture:** XGBoost (Gradient Boosted Trees)
- **Task:** Binary Classification (0 = Legitimate/Safe, 1 = Phishing/Malicious)

## Intended Use
- **Primary Use Case:** Real-time URL classification for the Anti-Phishing Chrome Extension.
- **Out of Scope:** Endpoint malware detection, deep content analysis (e.g., executing JavaScript or downloading binaries). 

## Features (Schema v2.0)
The v2.0 candidate model expands upon the v1.0 baseline (which only used 9 features) by incorporating structural URL characteristics to reduce false positives on long legitimate URLs.

**Baseline (9 Features):**
1. URL Length
2. Dot Count
3. Hyphen Count
4. At (@) Count
5. Double Slash (//) Count
6. Contains IP Address
7. Is HTTP (insecure)
8. Domain Entropy
9. Has Suspicious TLD (.top, .xyz, etc.)

**Added in v2.0 (7 Features):**
10. Hostname Length
11. Hostname Dot Count
12. Hostname Hyphen Count
13. Path Length
14. Path Slash Count
15. Query Length
16. Has Suspicious Keyword (e.g., login, verify, secure)

## Training Data & Methodology
- **Sources:** Mendeley Phishing Dataset, Kaggle Malicious Phish Dataset, New custom dataset.
- **Preprocessing:** 
  - Strict deduplication, dropping URLs with conflicting labels (64 records).
  - Explicit label mapping (Safe = 0, Phishing/Malicious = 1).
  - Domain-based holdout: Training, Validation, and Test sets strictly avoid domain overlap (e.g., `leetcode.com` only appears in Test).
- **Sampling:** 120,000 records (balanced) for reproducibility and efficient training.

## Performance Metrics (Held-Out Test Set)
Evaluated strictly on the held-out test set, with the decision threshold calibrated solely on the validation set.

| Metric | v1.0 (Baseline, 9 features) | v2.0 (Candidate, 16 features) | v3.0 (TF-IDF Char N-Grams) |
|---|---|---|---|
| **Accuracy** | 82.79% | 90.73% | 85.85% |
| **PR-AUC** | 0.9045 | 0.9706 | 0.9466 |
| **False Positive Rate (FPR)** | 16.60% | 8.02% | 15.08% |
| **False Negative Rate (FNR)** | 17.85% | 10.60% | 13.15% |
| **Phishing F1** | 0.8221 | 0.9032 | 0.8559 |

**Regression Checks (v1.0 / v2.0 / TF-IDF):**
- `leetcode.com` (Target): 0.7124 (Phish) / 0.5892 (Phish) / 0.3408 (Safe)
- `docs.caido.io`: 0.4938 (Safe) / 0.5547 (Phish) / 0.8031 (Phish)
- `github.com` (Deep link): 0.5296 (Phish) / 0.6808 (Phish) / 0.5359 (Phish)
- `wikipedia.org`: 0.8262 (Phish) / 0.5160 (Safe) / 0.1004 (Safe)
- `google.com` (Search): 0.4269 (Safe) / 0.5183 (Safe) / 0.8527 (Phish)

## Reproduction & Retraining Procedure
1. Add new labeled CSV datasets to `backend/training_data/`.
2. Run `python train_improved.py`.
3. The script will output validation metrics, regression checks, and save `xgboost_candidate.json`.
4. Review the holdout assertions in the output (e.g., no domain overlap).

## Staged Release & Shadow Mode
Before fully promoting the v2.0 model, it is deployed in **Shadow Mode**.
- The production API `/analyze` evaluates the URL using both models.
- The v1.0 model determines the actual HTTP response and extension behavior.
- The v2.0 model (candidate) computes its probability in the background.
- Both probabilities are logged (e.g., `[SHADOW MODE] URL: ... | Base Prob: ... | Cand Prob: ...`).
- After a monitoring period confirms that v2.0 reduces FPR without degrading protection (as seen in `docs.caido.io` regression), v1.0 will be decommissioned and v2.0 will become primary.

## Limitations & Ethical Considerations
- The model primarily inspects URL structure. Highly sophisticated attacks on compromised legitimate infrastructure (where URL structure is benign) might evade detection. 
- Over-reliance on TLDs and keyword heuristics can penalize legitimate new businesses. The improved schema mitigates this via length regularization.

## Release Gate / Recommendation
**Status: REJECTED FOR PRODUCTION**

Despite significant overall improvements in FPR and PR-AUC, neither the v2.0 Candidate Model nor the TF-IDF character n-gram model pass critical regression checks for legitimate deep links. The 16-feature schema naturally scores long paths on `leetcode.com`, `github.com`, and `docs.caido.io` above the validation threshold. The TF-IDF model successfully identifies `leetcode.com` but falsely flags `docs.caido.io`, `github.com`, and `google.com/search`.

**Conclusion:** URL structure and character n-grams alone are insufficient to distinguish deep legitimate links from phishing links reliably on this dataset. Because the dataset mixes generic phishing, malware, and defacement sites with legitimate sites, deep links trigger malicious patterns. Before replacing the production model, we must either:
1. Re-introduce an offline, bundled, privacy-safe reputation/whitelist mechanism (not relying on unbounded runtime downloads).
2. Gather a vastly more sophisticated dataset and engineer advanced semantic features that capture legitimate URL paths better.
