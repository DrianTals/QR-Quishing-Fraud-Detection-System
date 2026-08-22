# Quishing Scanner
### Machine Learning-Based Detection Model Application for QR Code Phishing (Quishing) Attacks Among Filipino Mobile Users

A capstone project that builds and evaluates a machine learning model for detecting QR code phishing ("quishing") attacks, packaged into a mobile-friendly application and tested with Filipino mobile users.

---

## Table of Contents
- [Overview](#overview)
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
- **Flask or FastAPI** — optional backend to serve the trained model to the app
- **Git/GitHub** — version control

### Frontend / App
- **Web-based**: HTML/CSS/JS or React (see `/app` — a working scanner SPA prototype)
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
🚧 In progress — outline and prototype scanner UI complete; dataset collection and model training in progress.
