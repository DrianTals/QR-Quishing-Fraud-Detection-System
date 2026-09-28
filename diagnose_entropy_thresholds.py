"""
Quick diagnostic: what are sensible thresholds for domain_entropy and
path_depth, based on the real distribution -- instead of guessing.
"""

import pandas as pd

FEATURES_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\processed\features.csv"

df = pd.read_csv(FEATURES_PATH)

print("=" * 60)
print("DOMAIN ENTROPY BY LABEL")
print("=" * 60)
print(df.groupby("label_name")["domain_entropy"].describe())

print("\n" + "=" * 60)
print("PATH DEPTH BY LABEL")
print("=" * 60)
print(df.groupby("label_name")["path_depth"].describe())
