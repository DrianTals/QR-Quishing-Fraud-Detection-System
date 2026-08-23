"""
Step: Generate synthetic QR images + merge into dataset
----------------------------------------------------------
Reads synthetic_ph_urls.csv (AI-generated PH-targeted URLs),
generates an actual QR code image for each one, saves them
alongside your real sampled images, and appends them to the
clean manifest so they flow into the same feature-extraction
and training pipeline — clearly tagged as synthetic.

Input:  synthetic_ph_urls.csv
        data/processed/qr_manifest_clean.csv (your real data)
Output: data/raw/qr_images_sample/benign/synthetic_*.png
        data/raw/qr_images_sample/malicious/synthetic_*.png
        data/processed/qr_manifest_with_synthetic.csv
"""

import csv
import os

import qrcode

SYNTHETIC_CSV = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\synthetic_ph_urls.csv"
REAL_MANIFEST = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\qr_manifest_clean.csv"
OUTPUT_MANIFEST = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\qr_manifest_with_synthetic.csv"
IMAGE_OUTPUT_ROOT = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\qr_images_sample"


def generate_qr_image(url, out_path):
    img = qrcode.make(url)
    img.save(out_path)


def main():
    # 1. Generate QR images for each synthetic URL, build new rows
    synthetic_rows = []
    with open(SYNTHETIC_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            label_name = row["label_name"]
            dest_folder = os.path.join(IMAGE_OUTPUT_ROOT, label_name)
            os.makedirs(dest_folder, exist_ok=True)

            filename = f"synthetic_{i:03d}.png"
            dest_path = os.path.join(dest_folder, filename)
            generate_qr_image(row["url"], dest_path)

            synthetic_rows.append({
                "filename": filename,
                "label": row["label"],
                "label_name": label_name,
                "url": row["url"],
                "decode_status": "ok",
                "ph_brand_mentioned": "",  # left blank here; your PH-brand filter step tags this later
                "source": "synthetic_ai",
            })

    # 2. Load real dataset rows, tag them as real
    real_rows = []
    with open(REAL_MANIFEST, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["source"] = "real_dataset"
            real_rows.append(row)

    # 3. Merge and save
    all_rows = real_rows + synthetic_rows
    fieldnames = ["filename", "label", "label_name", "url", "decode_status", "ph_brand_mentioned", "source"]

    with open(OUTPUT_MANIFEST, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    print(f"Generated {len(synthetic_rows)} synthetic QR images.")
    print(f"Merged dataset: {len(real_rows)} real + {len(synthetic_rows)} synthetic = {len(all_rows)} total rows.")
    print(f"Saved to: {OUTPUT_MANIFEST}")


if __name__ == "__main__":
    main()
