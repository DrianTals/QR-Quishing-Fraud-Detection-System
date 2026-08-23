"""
Step: Clean manifest + PH-brand relevance tagging
---------------------------------------------------
Reads data/raw/qr_manifest.csv, drops rows that failed to decode,
and adds a column flagging whether each URL mentions a Philippine
bank/e-wallet/gov brand name (regardless of label) — useful for
pulling out your PH-relevant subset for closer analysis or citation
in Chapter III/IV.

Input:  data/raw/qr_manifest.csv
Output: data/processed/qr_manifest_clean.csv
"""

import csv
import os

MANIFEST_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\qr_manifest.csv"
OUTPUT_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\qr_manifest_clean.csv"

PH_BRANDS = [
    "gcash", "paymaya", "maya", "bpi", "bdo", "metrobank",
    "unionbank", "landbank", "shopeepay", "shopee", "lazada",
    "grab", "gov.ph"
]


def has_ph_brand(url):
    url_lower = url.lower()
    for brand in PH_BRANDS:
        if brand in url_lower:
            return brand
    return ""


def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    kept_rows = []
    dropped = 0

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["decode_status"] != "ok" or not row["url"].strip():
                dropped += 1
                continue
            row["ph_brand_mentioned"] = has_ph_brand(row["url"])
            kept_rows.append(row)

    fieldnames = ["filename", "label", "label_name", "url", "decode_status", "ph_brand_mentioned"]
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(kept_rows)

    ph_matches = sum(1 for r in kept_rows if r["ph_brand_mentioned"])

    print(f"Kept {len(kept_rows)} rows, dropped {dropped} failed decodes.")
    print(f"PH-brand mentions found in {ph_matches} row(s).")
    print(f"Clean file saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
