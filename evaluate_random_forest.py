"""Evaluate the saved Random Forest on the reproducible held-out split."""

import argparse
import pickle
from pathlib import Path

import pandas as pd
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
from sklearn.model_selection import train_test_split

from train_random_forest import FEATURE_COLUMNS, FEATURES_PATH, MODEL_OUTPUT_PATH


def evaluate_model(features_path=FEATURES_PATH, model_path=MODEL_OUTPUT_PATH):
    features_path = Path(features_path)
    model_path = Path(model_path)
    if not features_path.is_file():
        raise FileNotFoundError(f"Feature dataset not found: {features_path}")
    if not model_path.is_file():
        raise FileNotFoundError(f"Trained model not found: {model_path}. Run train_random_forest.py first.")

    df = pd.read_csv(features_path)
    required_columns = {"label", *FEATURE_COLUMNS}
    missing_columns = sorted(required_columns.difference(df.columns))
    if missing_columns:
        raise ValueError(f"Feature dataset is missing columns: {', '.join(missing_columns)}")

    labels = pd.to_numeric(df["label"], errors="coerce")
    if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
        raise ValueError("The label column must contain only numeric 0 (benign) and 1 (malicious).")
    if labels.value_counts().reindex([0, 1], fill_value=0).min() < 2:
        raise ValueError("At least two rows from each class are required for a stratified split.")

    features = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0)
    y = labels.astype(int)
    _, X_test, _, y_test = train_test_split(
        features,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    with model_path.open("rb") as model_file:
        model = pickle.load(model_file)

    predictions = model.predict(X_test)
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("The saved model does not contain the malicious class (label 1).")
    probabilities = model.predict_proba(X_test)[:, classes.index(1)]

    accuracy = accuracy_score(y_test, predictions)
    balanced_accuracy = balanced_accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)
    false_positive_rate = None
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    if fp + tn:
        false_positive_rate = fp / (fp + tn)
    roc_auc = roc_auc_score(y_test, probabilities)

    print("RANDOM FOREST HELD-OUT EVALUATION")
    print(f"Model: {model_path}")
    print(f"Test rows: {len(y_test)} (same stratified 80/20 split used in training)")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"Balanced accuracy: {balanced_accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Malicious recall: {recall * 100:.2f}%")
    print(f"F1 score: {f1 * 100:.2f}%")
    print("False-positive rate: unavailable" if false_positive_rate is None else f"False-positive rate: {false_positive_rate * 100:.2f}%")
    print(f"ROC AUC: {roc_auc:.4f}")
    print(f"Confusion matrix [benign, malicious]: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("\nPer-class report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["benign", "malicious"],
        zero_division=0,
    ))
    print("Note: this is a random holdout score, not a guarantee of performance on new domains or live phishing.")

    return {
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "roc_auc": roc_auc,
        "test_rows": len(y_test),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate the saved Random Forest model.")
    parser.add_argument("--features", type=Path, default=FEATURES_PATH, help="Feature CSV used for training.")
    parser.add_argument("--model", type=Path, default=MODEL_OUTPUT_PATH, help="Saved Random Forest pickle.")
    args = parser.parse_args()
    evaluate_model(args.features, args.model)


if __name__ == "__main__":
    main()
