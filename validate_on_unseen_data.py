"""
Step: External validation — test the trained model on truly unseen data
----------------------------------------------------------------------------
The held-out test set in train_random_forest.py is still drawn from the
SAME dataset the model trained on, so a suspiciously perfect score there
doesn't prove the model generalizes — it might just mean the model found
a shortcut specific to how this dataset was built.

This script loads the saved model and tests it against:
  1. Your live PhishTank sample (real, currently-active phishing URLs
     the model has never seen)
  2. A hardcoded list of well-known legitimate sites (also never seen)

If accuracy here is meaningfully lower than the 100% test-set result,
that CONFIRMS the model was overfitting to a dataset artifact rather
than learning something that generalizes -- important, honest finding
for your paper.
"""

import os
import pickle
import glob
import re
import math
import warnings

import pandas as pd
from url_utils import extract_url_candidate, safe_parse

warnings.filterwarnings("ignore", category=UserWarning)

MODEL_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\model\random_forest.pkl"
RAW_DIR = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\raw"

FEATURE_COLUMNS = [
    "has_ip", "no_https", "has_at", "is_shortener", "bad_tld",
    "subdomain_count", "too_many_subdomains", "hyphen_count", "hyphen_heavy",
    "brand_mismatch", "suspicious_keyword",
    "punycode", "numeric_heavy", "is_free_hosting", "has_double_hyphen",
    "domain_entropy", "path_depth", "query_param_count",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "goo.gl",
              "rebrand.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id", "qr.net", "v.gd"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".zip", ".mov", ".rest", ".loan", ".cfd", ".sbs", ".shop", ".icu", ".buzz"]
SUSPICIOUS_KEYWORDS = ["verify", "login", "secure", "update", "confirm", "suspend",
                        "unlock", "otp", "claim", "reward", "reactivate", "validate"]
FREE_HOSTING_SUFFIXES = [
    "vercel.app", "replit.app", "netlify.app", "pages.dev", "webflow.io",
    "framer.website", "bolt.host", "duckdns.org", "github.io", "herokuapp.com",
    "glitch.me", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "azurewebsites.net", "ondigitalocean.app", "webcindario.com", "surge.sh",
    "000webhostapp.com",
]
PH_BRANDS = {
    "gcash": ["gcash.com"], "paymaya": ["maya.ph", "paymaya.com"], "maya": ["maya.ph"],
    "bpi": ["bpi.com.ph"], "bdo": ["bdo.com.ph"], "metrobank": ["metrobank.com.ph"],
    "unionbank": ["unionbankph.com"], "landbank": ["landbank.com"], "shopeepay": ["shopee.ph"],
    "shopee": ["shopee.ph"], "lazada": ["lazada.com.ph"], "grab": ["grab.com"],
}

KNOWN_LEGIT_URLS = [
    "https://www.google.com/", "https://www.facebook.com/", "https://www.amazon.com/",
    "https://www.microsoft.com/", "https://www.apple.com/", "https://www.wikipedia.org/",
    "https://www.youtube.com/", "https://www.netflix.com/", "https://www.gcash.com/",
    "https://maya.ph/", "https://www.bpi.com.ph/", "https://www.bdo.com.ph/",
    "https://shopee.ph/", "https://www.lazada.com.ph/", "https://www.grab.com/ph/en/",
    "https://www.rappler.com/", "https://www.philstar.com/", "https://www.dict.gov.ph/",
]


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 4)


def extract_features(raw_url):
    normalized_url = extract_url_candidate(raw_url)
    parsed = safe_parse(normalized_url)
    if parsed is None or not parsed.hostname:
        return None

    host = parsed.hostname.lower()
    full = normalized_url.lower()

    is_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) else 0
    no_https = 0 if parsed.scheme == "https" else 1
    has_at = 1 if "@" in full else 0
    is_shortener = 1 if any(host == s or host.endswith("." + s) for s in SHORTENERS) else 0
    bad_tld = 1 if any(host.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    subdomain_count = max(host.count(".") - 1, 0)
    too_many_subdomains = 1 if subdomain_count > 3 else 0
    hyphen_count = host.count("-")
    hyphen_heavy = 1 if hyphen_count >= 2 else 0

    brand_mismatch = 0
    for brand, official_list in PH_BRANDS.items():
        if brand in full:
            matches_official = any(host == d or host.endswith("." + d) for d in official_list)
            if not matches_official:
                brand_mismatch = 1
            break

    suspicious_keyword = 1 if any(k in full for k in SUSPICIOUS_KEYWORDS) else 0
    punycode = 1 if "xn--" in host else 0
    numeric_heavy = 1 if sum(c.isdigit() for c in host) >= 4 else 0
    is_free_hosting = 1 if any(host.endswith(s) for s in FREE_HOSTING_SUFFIXES) else 0
    has_double_hyphen = 1 if "--" in host else 0
    domain_entropy = shannon_entropy(host)
    path_depth = parsed.path.count("/") if parsed.path else 0
    query_param_count = parsed.query.count("&") + 1 if parsed.query else 0

    return {
        "has_ip": is_ip, "no_https": no_https, "has_at": has_at, "is_shortener": is_shortener,
        "bad_tld": bad_tld, "subdomain_count": subdomain_count, "too_many_subdomains": too_many_subdomains,
        "hyphen_count": hyphen_count, "hyphen_heavy": hyphen_heavy, "brand_mismatch": brand_mismatch,
        "suspicious_keyword": suspicious_keyword, "punycode": punycode, "numeric_heavy": numeric_heavy,
        "is_free_hosting": is_free_hosting, "has_double_hyphen": has_double_hyphen,
        "domain_entropy": domain_entropy, "path_depth": path_depth, "query_param_count": query_param_count,
    }


def load_phishtank_urls():
    pattern = os.path.join(RAW_DIR, "phishtank_live_sample_*.txt")
    files = glob.glob(pattern)
    if not files:
        return []
    latest = max(files, key=os.path.getmtime)
    urls = []
    with open(latest, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    print(f"Loaded {len(urls)} live phishing URLs from: {os.path.basename(latest)}")
    return urls


def main():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    phish_urls = load_phishtank_urls()
    legit_urls = KNOWN_LEGIT_URLS

    print("\n" + "=" * 60)
    print("TESTING ON REAL LIVE PHISHING URLS (should predict malicious=1)")
    print("=" * 60)
    correct = 0
    for url in phish_urls:
        feats = extract_features(url)
        if feats is None:
            continue
        row = pd.DataFrame([[feats[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        pred = model.predict(row)[0]
        proba = model.predict_proba(row)[0][1]
        status = "CORRECT" if pred == 1 else "MISSED"
        if pred == 1:
            correct += 1
        print(f"  [{status:8}] score={proba:.2f}  {url[:70]}")
    if phish_urls:
        print(f"\nCaught {correct}/{len(phish_urls)} live phishing URLs ({correct/len(phish_urls)*100:.1f}%)")

    print("\n" + "=" * 60)
    print("TESTING ON KNOWN LEGITIMATE SITES (should predict malicious=0)")
    print("=" * 60)
    correct_legit = 0
    for url in legit_urls:
        feats = extract_features(url)
        row = pd.DataFrame([[feats[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        pred = model.predict(row)[0]
        proba = model.predict_proba(row)[0][1]
        status = "CORRECT" if pred == 0 else "FALSE ALARM"
        if pred == 0:
            correct_legit += 1
        print(f"  [{status:12}] score={proba:.2f}  {url}")
    print(f"\nCorrectly passed {correct_legit}/{len(legit_urls)} legit sites ({correct_legit/len(legit_urls)*100:.1f}%)")


if __name__ == "__main__":
    main()
