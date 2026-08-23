"""
Step: Sample + Decode QR Dataset
---------------------------------
Takes your downloaded benign/ and malicious/ QR image folders,
randomly samples a manageable subset of each, decodes every QR
image back into its original URL, and writes everything into a
single labeled manifest CSV.

Output columns: filename, label (0=benign, 1=malicious), url, decode_status

Uses OpenCV's built-in QR decoder (no external zbar DLL needed).

Run this locally (with Python installed) or in Google Colab.
"""

import os
import csv
import random
import shutil

import cv2

# ---------------- CONFIG — edit these paths ----------------
BENIGN_SRC = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\benign\benign\benign"
MALICIOUS_SRC = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\malicious\malicious"

SAMPLE_SIZE_PER_CLASS = 750            # adjust as needed (500-1000 is plenty)

OUTPUT_DIR = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\qr_images_sample"
MANIFEST_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\raw\qr_manifest.csv"
# -------------------------------------------------------------

qr_detector = cv2.QRCodeDetector()


def sample_files(src_folder, n):
    all_files = [f for f in os.listdir(src_folder) if f.lower().endswith((".png", ".jpg", ".jpeg"))]
    if len(all_files) < n:
        print(f"  Warning: only {len(all_files)} files found in {src_folder}, using all of them.")
        n = len(all_files)
    return random.sample(all_files, n)


def decode_qr(image_path):
    try:
        img = cv2.imread(image_path)
        if img is None:
            return "", "error:could_not_read_image"
        data, points, _ = qr_detector.detectAndDecode(img)
        if data:
            return data, "ok"
        return "", "no_qr_detected"
    except Exception as e:
        return "", f"error:{e}"


def process_class(src_folder, label, label_name, dest_root):
    print(f"Sampling {SAMPLE_SIZE_PER_CLASS} files from '{label_name}'...")
    files = sample_files(src_folder, SAMPLE_SIZE_PER_CLASS)

    dest_folder = os.path.join(dest_root, label_name)
    os.makedirs(dest_folder, exist_ok=True)

    rows = []
    for i, fname in enumerate(files, 1):
        src_path = os.path.join(src_folder, fname)
        dest_path = os.path.join(dest_folder, fname)
        shutil.copy(src_path, dest_path)

        url, status = decode_qr(dest_path)
        rows.append({
            "filename": fname,
            "label": label,
            "label_name": label_name,
            "url": url,
            "decode_status": status
        })

        if i % 100 == 0:
            print(f"  {label_name}: {i}/{len(files)} decoded")

    return rows


def main():
    random.seed(42)  # reproducible sampling
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)

    all_rows = []
    all_rows += process_class(BENIGN_SRC, 0, "benign", OUTPUT_DIR)
    all_rows += process_class(MALICIOUS_SRC, 1, "malicious", OUTPUT_DIR)

    with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "label", "label_name", "url", "decode_status"])
        writer.writeheader()
        writer.writerows(all_rows)

    ok_count = sum(1 for r in all_rows if r["decode_status"] == "ok")
    print(f"\nDone. {ok_count}/{len(all_rows)} QR codes decoded successfully.")
    print(f"Manifest saved to: {MANIFEST_PATH}")
    print(f"Sampled images saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()