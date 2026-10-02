# Quishing Scanner
### Machine Learning-Based Detection Model Application for QR Code Phishing (Quishing) Attacks Among Filipino Mobile Users

A capstone project that builds and evaluates a machine learning model for detecting QR code phishing ("quishing") attacks, packaged into a mobile-friendly application and tested with Filipino mobile users.

---

## Table of Contents
- [Overview](#overview)
- [How the Web Scanner Works](#how-the-web-scanner-works)
- [Run the Project Step by Step](#run-the-project-step-by-step)
- [Project Outline](#project-outline)
- [Requirements](#requirements)
  - [Datasets](#datasets)
  - [Core Tools & Frameworks](#core-tools--frameworks)
  - [Frontend / App](#frontend--app)
  - [AI Agent (optional scope)](#ai-agent-optional-scope)
  - [People](#people)
  - [Hardware](#hardware)
  - [Compliance & Ethics](#compliance--ethics)
- [Known Risks](#known-risks)
- [Repo Structure](#suggested-repo-structure)
- [Status](#status)

---

## Overview

QR codes are now routine in the Philippines — e-wallet payments, restaurant menus, government forms — and quishing exploits that trust by embedding malicious links inside QR codes, often bypassing conventional URL-based phishing filters. This project trains an ML classifier to flag risky QR-embedded links and wraps it in a usable scanning app, then validates both the model's accuracy and the app's usability with real users.

## How the Web Scanner Works

The scanner can read a QR code from an uploaded image or from your device camera:

1. The browser uses the `jsQR` decoder to read the QR code and extract its text. Camera use requires permission from your browser.
2. The extracted text is sent to the locally running Python server. The server normalizes it to a URL and extracts features such as HTTPS usage, domain structure, and suspicious keywords.
3. The saved Random Forest model evaluates those features and returns a risk score, verdict, and detected signals for the page to display.

The QR image and camera frames are processed in the browser. Only the decoded text is sent to the local API, and the API analyzes the URL as text without opening or fetching it. A result is a risk estimate, not a guarantee that a link is safe or malicious.

## Run the Project Step by Step

Run these commands from the repository root in PowerShell. The full data pipeline starts with QR image files; if you already have a current `data/processed/features.csv`, skip steps 2–6 and continue at model training.

Run only the commands inside the PowerShell code blocks; the surrounding text explains what each command does.

### 1. Set up Python

Create a virtual environment and install the project dependencies:

```powershell
py -m venv .venv
$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt
```

If the `py` launcher is unavailable, use `python -m venv .venv` for the first command.

### 2. Prepare QR image inputs

Place the source images in the folders configured in `sample_and_decode_qr.py`:

- Benign images: `data/raw/benign/benign/benign/`
- Malicious images: `data/raw/malicious/malicious/`

Each folder should contain `.png`, `.jpg`, or `.jpeg` QR images. If your images are stored elsewhere, update `BENIGN_SRC` and `MALICIOUS_SRC` in that script before running it.

### 3. Decode the QR images

```powershell
& $Python sample_and_decode_qr.py
```

This samples up to 750 images per class, decodes the QR contents, copies the sampled images into `data/raw/qr_images_sample/`, and writes `data/raw/qr_manifest.csv`. The manifest records the label, extracted URL, and decode status.

### 4. Clean and tag the manifest

```powershell
& $Python clean_and_tag_ph_brands.py
```

This drops failed decodes, tags Philippine brand mentions, and writes `data/processed/qr_manifest_clean.csv`.

### 5. Add synthetic examples

```powershell
& $Python generate_synthetic_qr.py
```

This reads `synthetic_ph_urls.csv` and the clean manifest, generates synthetic QR images, and writes the merged `data/processed/qr_manifest_with_synthetic.csv`.

### 6. Extract URL features

```powershell
& $Python extract_features.py
```

This normalizes decoded text to its embedded URL, extracts model features, and writes `data/processed/features.csv`.

### 7. Train and evaluate the Random Forest

```powershell
& $Python train_random_forest.py
```

This trains the classifier using a stratified 80/20 train/test split and saves `model/random_forest.pkl` plus held-out row predictions in `data/processed/ml_evaluation_results.csv`. Metrics, a threshold sweep, and feature importances are printed in the terminal.

To test training without replacing those default outputs, specify separate destinations:

```powershell
& $Python train_random_forest.py --model-output model/test_random_forest.pkl --results-output data/processed/test_predictions.csv
```

### 8. Check the saved Random Forest accuracy

```powershell
& $Python evaluate_random_forest.py
```

This loads the saved model and evaluates it on the same reproducible stratified 80/20 holdout used during training. It prints accuracy as a percentage, along with balanced accuracy, precision, malicious recall, F1, false-positive rate, ROC AUC, and the confusion matrix. It does not retrain the model or overwrite the saved model. This random-holdout score is not a guarantee of performance on new domains or live phishing URLs.

### 9. Optionally evaluate the rule-based baseline

```powershell
& $Python evaluate_rule_based.py
```

This writes `data/processed/evaluation_results.csv`. It is a separate rule-based research baseline; the browser scanner uses the Random Forest model.

### 10. Optionally validate against fresh URLs

Fetch the latest PhishTank sample, then run the external validation script:

```powershell
& $Python fetch_live_phishtank_sample.py
& $Python validate_on_unseen_data.py
```

The validation script also checks a small list of known legitimate sites. The PhishTank page scraper may capture unrelated page links, so inspect the sample before interpreting the result. `fetch_live_phishing_sample.py` separately saves up to 15 OpenPhish URLs for manual scanner testing; it is not part of model training. Treat these live URLs as text only and never open them.

### 11. Start the scanner

```powershell
& $Python server.py
```

Open `http://127.0.0.1:8765` in a browser. Upload a QR image, scan with the camera, or paste a URL. QR decoding happens in the browser; the extracted text is sent to the local API for feature extraction and Random Forest prediction. The API does not fetch or open the submitted URL. Stop the server with `Ctrl+C`.

**Path note:** Several data-pipeline scripts still contain absolute paths for this Windows checkout. If you move or clone the repository to a different location, update the path constants near the top of those scripts before running the pipeline.

---

## Project Outline

### Chapter I — The Problem and Its Background
- Introduction
- Background of the Study
- Statement of the Problem
- Objectives of the Study
- Significance of the Study
- Scope and Limitations
- Definition of Terms

### Chapter II — Review of Related Literature and Studies
- Related Literature
- Related Studies (Foreign)
- Related Studies (Local)
- Synthesis
- Theoretical Framework
- Conceptual Framework

### Chapter III — Research Methodology
- Research Design
- Data Gathering
- Feature Extraction
- Model Development
- Training and Validation
- Evaluation Metrics
- Mobile Application Development
- User Acceptance Testing
- Ethical Considerations

### Chapter IV — Presentation, Analysis, and Interpretation of Data
- Model Performance Comparison
- Feature Importance Analysis
- System Usability Results
- Discussion

### Chapter V — Summary, Conclusion, and Recommendations
- Summary of Findings
- Conclusions
- Recommendations

### References & Appendices
- References
- Sample dataset entries, survey instrument, consent form, source code link

---

## Requirements

### Datasets

| Type | Source | Notes |
|---|---|---|
| Malicious URLs | [PhishTank](https://phishtank.org/), [OpenPhish](https://openphish.com/), [URLhaus](https://urlhaus.abuse.ch/), PhishStats | Free, regularly updated feeds |
| Benign URLs | [Tranco](https://tranco-list.eu/) or Majestic Million top-sites list | Add official PH bank/e-wallet/gov domains manually (gcash.com, maya.ph, bpi.com.ph, etc.) |
| QR image data | Self-generated | Encode the URL datasets above into QR images (e.g., Python `qrcode`) — real quishing-QR image datasets are rare, so this is usually built, not found |
| Local/PH scam samples | DICT, NPC, BSP public advisories | Good for validating the model against real reported local cases — cite properly, don't scrape aggressively |
| Usability data | Self-collected | UAT survey (e.g., System Usability Scale) from your own respondents |

### Core Tools & Frameworks
- **Python** — pandas, numpy for data wrangling
- **scikit-learn** — Random Forest, SVM, Naive Bayes, etc.
- **TensorFlow/Keras or PyTorch** — if using CNN/LSTM on URL sequences
- **Google Colab or Jupyter** — training environment (Colab's free GPU tier is usually enough)
- **`qrcode`** (Python) — generate QR images from URLs
- **`pyzbar` / `opencv-python`** or **`jsQR`** (JS) — decode QR images
- **Python standard library `http.server`** — serves the scanner and local prediction API
- **Git/GitHub** — version control

### Frontend / App
- **Web-based**: `index.html` is the scanner UI; `server.py` serves it and provides local Random Forest predictions.
- **Native mobile**: Flutter or React Native, with the trained model exported to **TensorFlow Lite** for on-device inference
- **Architecture decision to make early**: on-device model (offline, faster, harder to deploy/update) vs. API call to a hosted model (easier to update, needs internet + hosting)

### AI Agent (optional scope)
Two different things this could mean — decide which applies to your project:
1. **Development aid** — using an AI coding assistant (e.g., Claude Code, GitHub Copilot) to help build and debug the pipeline. Reasonable to use and disclose.
2. **In-app agentic feature** — an LLM-based agent that explains *why* a QR was flagged in plain language, or that fetches/analyzes WHOIS data before scoring. Optional scope expansion, not required for the core detection model.

### People
- Thesis adviser and panel
- A cybersecurity practitioner or IT admin to sanity-check feature choices
- UAT respondents — spread across ages/tech-literacy levels to support the study's significance claims

### Hardware
- Any laptop for training (Colab free tier covers most model sizes needed here)
- 2–3 Android devices for cross-device camera-scanning tests

### Compliance & Ethics
- **Data Privacy Act (RA 10173)** coverage for UAT data — informed consent form, anonymized responses
- School research ethics clearance if required — include a short safety note that the study only *analyzes* links and never visits/executes them

---

## Known Risks
- **Class imbalance** between malicious and benign samples — decide early whether to undersample, oversample (SMOTE), or use class-weighted loss, since it affects both model results and how you write up Chapter III/IV.
- **Dataset staleness** — phishing URL feeds change fast; document the date range your dataset was pulled from.
- **Small local sample size** — PH-specific quishing examples may be limited; be explicit in Chapter III about how this was mitigated (e.g., synthetic QR generation from real malicious URLs).

---

## Suggested Repo Structure
```
├── data/
│   ├── raw/              # untouched source datasets
│   └── processed/        # cleaned, feature-extracted datasets
├── notebooks/            # training/evaluation notebooks
├── model/                # exported trained model(s)
├── app/                  # frontend SPA / mobile app source
├── docs/                 # thesis chapters, diagrams, survey instrument
└── README.md
```

---

## Status
🚧 In progress — the QR-to-feature pipeline and local Random Forest scanner are implemented. Broader independent validation and user testing are still needed before treating the reported metrics as general performance.
