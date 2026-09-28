"""
Step: Train a real ML model (Random Forest)
------------------------------------------------
Loads features.csv, splits it into training/testing sets,
trains a Random Forest classifier, and reports held-out
classification metrics and feature importances.

Also prints feature importances, showing which signals the model
actually learned matter most (compare this to the hand-picked
weights in the rule-based version — this is your "ML vs rules"
Chapter IV comparison).

Input:  data/processed/features.csv
Output: prints metrics + feature importances to the terminal
        saves the trained model to model/random_forest.pkl
        saves per-row test predictions to data/processed/ml_evaluation_results.csv
"""

import argparse
import json
import pickle
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT_DIR = Path(__file__).resolve().parent
FEATURES_PATH = ROOT_DIR / "data" / "processed" / "features.csv"
MODEL_OUTPUT_PATH = ROOT_DIR / "model" / "random_forest.pkl"
RESULTS_PATH = ROOT_DIR / "data" / "processed" / "ml_evaluation_results.csv"

# The local prediction API uses this same ordered feature list.
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


def train_model(features_path, model_output_path, results_path):
    features_path = Path(features_path)
    model_output_path = Path(model_output_path)
    results_path = Path(results_path)
    if not features_path.is_file():
        raise FileNotFoundError(f"Feature dataset not found: {features_path}")

    df = pd.read_csv(features_path)
    if df.empty:
        raise ValueError(f"Feature dataset is empty: {features_path}")

    required_columns = {"filename", "url", "label", *FEATURE_COLUMNS}
    missing_columns = sorted(required_columns.difference(df.columns))
    if missing_columns:
        raise ValueError(f"Feature dataset is missing columns: {', '.join(missing_columns)}")

    labels = pd.to_numeric(df["label"], errors="coerce")
    if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
        raise ValueError("The label column must contain only numeric 0 (benign) and 1 (malicious).")
    if labels.value_counts().reindex([0, 1], fill_value=0).min() < 5:
        raise ValueError("At least five rows from each class are required for a stratified train/test split.")
    df["label"] = labels.astype(int)

    for col in FEATURE_COLUMNS:
        numeric_values = pd.to_numeric(df[col], errors="coerce")
        invalid_count = int(numeric_values.isna().sum())
        if invalid_count:
            print(f"Warning: replacing {invalid_count} invalid value(s) in feature '{col}' with 0.")
        df[col] = numeric_values.fillna(0)

    X = df[FEATURE_COLUMNS]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training on {len(X_train)} rows, testing on {len(X_test)} rows.")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    positive_class_index = list(model.classes_).index(1)
    y_proba = model.predict_proba(X_test)[:, positive_class_index]

    accuracy = accuracy_score(y_test, y_pred)
    balanced_accuracy = balanced_accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0
    roc_auc = roc_auc_score(y_test, y_proba)

    print("=" * 50)
    print("RANDOM FOREST RESULTS (default 0.5 threshold)")
    print("=" * 50)
    print(f"True Positives:  {tp}")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print("-" * 50)
    print(f"Accuracy:            {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"Balanced accuracy:   {balanced_accuracy:.4f}")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1-score:            {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"ROC AUC:             {roc_auc:.4f}")
    print("\nPer-class report:")
    print(classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["benign", "malicious"],
        zero_division=0,
    ))
    print("-" * 50)

    print("\nTHRESHOLD SWEEP — trading precision for recall:")
    print(f"{'Threshold':<12}{'Accuracy':<12}{'Precision':<12}{'Recall':<12}{'F1':<12}{'FPR':<10}")
    for t in [0.5, 0.4, 0.3, 0.25, 0.2, 0.15, 0.1]:
        y_pred_t = (y_proba >= t).astype(int)
        acc_t = accuracy_score(y_test, y_pred_t)
        prec_t = precision_score(y_test, y_pred_t, zero_division=0)
        rec_t = recall_score(y_test, y_pred_t, zero_division=0)
        f1_t = f1_score(y_test, y_pred_t, zero_division=0)
        tn_t, fp_t, fn_t, tp_t = confusion_matrix(y_test, y_pred_t, labels=[0, 1]).ravel()
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
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    with model_output_path.open("wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {model_output_path}")

    metrics = {
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "roc_auc": roc_auc,
        "test_rows": int(len(y_test)),
        "split": "stratified 80/20 holdout, random_state=42",
    }
    metrics_path = model_output_path.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(f"Held-out metrics saved to: {metrics_path}")

    results_df = df.loc[X_test.index, ["filename", "url", "label"]].copy()
    results_df["predicted"] = y_pred
    results_df["malicious_probability"] = y_proba
    results_df["correct"] = results_df["label"] == results_df["predicted"]
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(results_path, index=False)
    print(f"Per-row test results saved to: {results_path}")

    return model


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate the quishing Random Forest model.")
    parser.add_argument("--features", type=Path, default=FEATURES_PATH, help="Input features CSV.")
    parser.add_argument("--model-output", type=Path, default=MODEL_OUTPUT_PATH, help="Output pickle path.")
    parser.add_argument("--results-output", type=Path, default=RESULTS_PATH, help="Held-out predictions CSV.")
    args = parser.parse_args()
    train_model(args.features, args.model_output, args.results_output)


if __name__ == "__main__":
    main()
