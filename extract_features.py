"""
Step: Feature Extraction
-------------------------
Reads data/processed/qr_manifest_clean.csv and converts every URL
into a row of numeric/binary features — the same signal categories
used in the rule-based scanner engine (IP address, shortener,
suspicious TLD, brand mismatch, punycode, etc.).

This feature table is what either the rule-based scorer or an ML
model (e.g. RandomForestClassifier) will actually be trained/tested on.

Input:  data/processed/qr_manifest_clean.csv
Output: data/processed/features.csv
"""

import csv
import os
import re
import math
from urllib.parse import urlparse

INPUT_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\qr_manifest_with_synthetic.csv"
OUTPUT_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\features.csv"

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "goo.gl",
              "rebrand.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id", "qr.net", "v.gd"]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".zip", ".mov", ".rest", ".loan", ".cfd", ".sbs", ".shop", ".icu", ".buzz"]

SUSPICIOUS_KEYWORDS = ["verify", "login", "secure", "update", "confirm", "suspend",
                        "unlock", "otp", "claim", "reward", "reactivate", "validate"]

# Free app-deployment platforms commonly abused for phishing: attackers get an
# instant, legitimate-looking HTTPS subdomain with zero registration scrutiny.
# Identified from real live-phishing validation testing (see validate_on_unseen_data.py).
FREE_HOSTING_SUFFIXES = [
    "vercel.app", "replit.app", "netlify.app", "pages.dev", "webflow.io",
    "framer.website", "bolt.host", "duckdns.org", "github.io", "herokuapp.com",
    "glitch.me", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "azurewebsites.net", "ondigitalocean.app", "webcindario.com", "surge.sh",
    "000webhostapp.com",
]

PH_BRANDS = {
    "gcash": ["gcash.com"],
    "paymaya": ["maya.ph", "paymaya.com"],
    "maya": ["maya.ph"],
    "bpi": ["bpi.com.ph"],
    "bdo": ["bdo.com.ph"],
    "metrobank": ["metrobank.com.ph"],
    "unionbank": ["unionbankph.com"],
    "landbank": ["landbank.com"],
    "shopeepay": ["shopee.ph"],
    "shopee": ["shopee.ph"],
    "lazada": ["lazada.com.ph"],
    "grab": ["grab.com"],
}


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def safe_parse(raw_url):
    try:
        candidate = raw_url.strip()
        if not re.match(r"^https?://", candidate, re.IGNORECASE):
            candidate = "http://" + candidate
        return urlparse(candidate)
    except Exception:
        return None


def extract_features(raw_url):
    parsed = safe_parse(raw_url)
    if parsed is None or not parsed.hostname:
        # Unparseable URL — return a row flagged accordingly, rest zeroed
        return {
            "url_parseable": 0, "has_ip": 0, "no_https": 1, "has_at": 0,
            "is_shortener": 0, "bad_tld": 0, "subdomain_count": 0,
            "too_many_subdomains": 0, "hyphen_count": 0, "hyphen_heavy": 0,
            "brand_mismatch": 0, "brand_mentioned": "", "suspicious_keyword": 0,
            "url_length": len(raw_url), "is_long": 1 if len(raw_url) > 75 else 0,
            "punycode": 0, "numeric_heavy": 0, "is_free_hosting": 0, "has_double_hyphen": 0,
            "domain_length": 0, "digit_ratio_domain": 0,
            "domain_entropy": 0, "path_depth": 0, "query_param_count": 0,
        }

    host = parsed.hostname.lower()
    full = raw_url.lower()

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
    brand_mentioned = ""
    for brand, official_list in PH_BRANDS.items():
        if brand in full:
            matches_official = any(host == d or host.endswith("." + d) for d in official_list)
            if not matches_official:
                brand_mismatch = 1
                brand_mentioned = brand
            break

    suspicious_keyword = 1 if any(k in full for k in SUSPICIOUS_KEYWORDS) else 0
    url_length = len(raw_url)
    is_long = 1 if url_length > 75 else 0
    punycode = 1 if "xn--" in host else 0
    numeric_heavy = 1 if sum(c.isdigit() for c in host) >= 4 else 0
    is_free_hosting = 1 if any(host.endswith(s) for s in FREE_HOSTING_SUFFIXES) else 0
    has_double_hyphen = 1 if "--" in host else 0

    # --- Richer continuous features (added after diagnostics showed binary-only
    # features gave the model too little resolution to find a workable threshold) ---
    domain_length = len(host)
    digit_count_domain = sum(c.isdigit() for c in host)
    digit_ratio_domain = round(digit_count_domain / len(host), 4) if len(host) else 0

    domain_entropy = shannon_entropy(host)

    path_and_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    path_depth = parsed.path.count("/") if parsed.path else 0
    query_param_count = parsed.query.count("&") + 1 if parsed.query else 0

    return {
        "url_parseable": 1, "has_ip": is_ip, "no_https": no_https, "has_at": has_at,
        "is_shortener": is_shortener, "bad_tld": bad_tld, "subdomain_count": subdomain_count,
        "too_many_subdomains": too_many_subdomains, "hyphen_count": hyphen_count,
        "hyphen_heavy": hyphen_heavy, "brand_mismatch": brand_mismatch,
        "brand_mentioned": brand_mentioned, "suspicious_keyword": suspicious_keyword,
        "url_length": url_length, "is_long": is_long, "punycode": punycode,
        "numeric_heavy": numeric_heavy, "is_free_hosting": is_free_hosting,
        "has_double_hyphen": has_double_hyphen,
        "domain_length": domain_length, "digit_ratio_domain": digit_ratio_domain,
        "domain_entropy": domain_entropy, "path_depth": path_depth,
        "query_param_count": query_param_count,
    }


def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    rows_out = []
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = extract_features(row["url"])
            out_row = {
                "filename": row["filename"],
                "label": row["label"],
                "label_name": row["label_name"],
                "url": row["url"],
                **features,
            }
            rows_out.append(out_row)

    fieldnames = list(rows_out[0].keys()) if rows_out else []
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    print(f"Extracted features for {len(rows_out)} URLs.")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
