"""
Quick diagnostic: is url_length a real signal or a dataset artifact?
------------------------------------------------------------------------
Compares average/median URL length between benign and malicious rows,
and shows the same breakdown split by source (real_dataset vs
synthetic_ai) to check whether the difference is driven by how the
dataset was assembled rather than a genuine phishing pattern.
"""

import pandas as pd

FEATURES_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\processed\features.csv"
MANIFEST_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\processed\qr_manifest_with_synthetic.csv"

df = pd.read_csv(FEATURES_PATH)
manifest = pd.read_csv(MANIFEST_PATH)[["filename", "source"]]
df = df.merge(manifest, on="filename", how="left")

print("=" * 60)
print("URL LENGTH BY LABEL (all rows)")
print("=" * 60)
print(df.groupby("label_name")["url_length"].agg(["mean", "median", "min", "max", "count"]))

print("\n" + "=" * 60)
print("URL LENGTH BY LABEL, SPLIT BY SOURCE")
print("=" * 60)
print(df.groupby(["source", "label_name"])["url_length"].agg(["mean", "median", "count"]))

print("\n" + "=" * 60)
print("SAMPLE URLS — shortest benign vs shortest malicious")
print("=" * 60)
print("\nShortest benign URLs:")
print(df[df["label_name"] == "benign"].nsmallest(5, "url_length")[["url", "url_length"]].to_string(index=False))
print("\nShortest malicious URLs:")
print(df[df["label_name"] == "malicious"].nsmallest(5, "url_length")[["url", "url_length"]].to_string(index=False))
