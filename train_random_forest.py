"""
Step: Train a real ML model (Random Forest)
------------------------------------------------
Loads features.csv, splits it into training/testing sets,
trains a Random Forest classifier on the same features used by
the rule-based scorer, and reports accuracy/precision/recall/F1 —
directly comparable to evaluate_rule_based.py's output.

Also prints feature importances, showing which signals the model
actually learned matter most (compare this to the hand-picked
weights in the rule-based version — this is your "ML vs rules"
Chapter IV comparison).

Input:  data/processed/features.csv
Output: prints metrics + feature importances to the terminal
        saves the trained model to model/random_forest.pkl
        saves per-row test predictions to data/processed/ml_evaluation_results.csv
"""

import os
import pickle

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

FEATURES_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\features.csv"
MODEL_OUTPUT_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\model\random_forest.pkl"
RESULTS_PATH = r"C:\Users\User\Desktop\QR-Quishing-Fraud-Detection-System\data\processed\ml_evaluation_results.csv"

# Same feature columns the rule-based scorer uses — keeping this identical
# is what makes the comparison between the two approaches fair.
# NOTE: url_length / is_long were removed after diagnostics showed the real
# dataset had almost no length difference between classes (78.75 vs 79.73
# chars on average) — the model's earlier 87% reliance on url_length was
# exploiting a dataset artifact, not a genuine phishing signal, and would
# likely not generalize to real-world URLs scanned through the app.
# NOTE: domain_length and digit_ratio_domain were REMOVED after live
# validation testing confirmed they were dataset-specific artifacts —
# they drove the model to 100% accuracy on the held-out test set, but
# only 20% recall (5/25) against real, currently-active phishing URLs.
# is_free_hosting / has_double_hyphen were added after that same live
# test revealed a real, recurring pattern: phishing pages hosted on free
# app-deployment platforms (Replit, Vercel, Bolt.host, etc.) with
# auto-generated "brand-keyword--username" style subdomains.
FEATURE_COLUMNS = [
    "has_ip", "no_https", "has_at", "is_shortener", "bad_tld",
    "subdomain_count", "too_many_subdomains", "hyphen_count", "hyphen_heavy",
    "brand_mismatch", "suspicious_keyword",
    "punycode", "numeric_heavy", "is_free_hosting", "has_double_hyphen",
    "domain_entropy", "path_depth", "query_param_count",
]


def main():
    df = pd.read_csv(FEATURES_PATH)

    # Make sure feature columns are numeric (they're stored as 0/1 strings in the CSV)
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    X = df[FEATURE_COLUMNS]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training on {len(X_train)} rows, testing on {len(X_test)} rows.")

    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]  # probability of "malicious"

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0

    print("=" * 50)
    print("RANDOM FOREST RESULTS (default 0.5 threshold)")
    print("=" * 50)
    print(f"True Positives:  {tp}")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print("-" * 50)
    print(f"Accuracy:            {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1-score:            {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print("-" * 50)

    print("\nTHRESHOLD SWEEP — trading precision for recall:")
    print(f"{'Threshold':<12}{'Accuracy':<12}{'Precision':<12}{'Recall':<12}{'F1':<12}{'FPR':<10}")
    for t in [0.5, 0.4, 0.3, 0.25, 0.2, 0.15, 0.1]:
        y_pred_t = (y_proba >= t).astype(int)
        acc_t = accuracy_score(y_test, y_pred_t)
        prec_t = precision_score(y_test, y_pred_t, zero_division=0)
        rec_t = recall_score(y_test, y_pred_t, zero_division=0)
        f1_t = f1_score(y_test, y_pred_t, zero_division=0)
        tn_t, fp_t, fn_t, tp_t = confusion_matrix(y_test, y_pred_t).ravel()
        fpr_t = fp_t / (fp_t + tn_t) if (fp_t + tn_t) else 0
        print(f"{t:<12}{acc_t:<12.4f}{prec_t:<12.4f}{rec_t:<12.4f}{f1_t:<12.4f}{fpr_t:<10.4f}")

    print("\nFeature importances (what the model actually learned matters most):")
    importances = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for feature, importance in importances:
        print(f"  {feature:<25} {importance:.4f}")

    # Save the trained model
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    with open(MODEL_OUTPUT_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")

    # Save per-row test results for inspection
    results_df = df.loc[idx_test, ["filename", "url", "label"]].copy()
    results_df["predicted"] = y_pred
    results_df["correct"] = results_df["label"] == results_df["predicted"]
    results_df.to_csv(RESULTS_PATH, index=False)
    print(f"Per-row test results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
