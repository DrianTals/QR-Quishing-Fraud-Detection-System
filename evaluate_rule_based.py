"""
Step: Evaluate the rule-based scorer against the full dataset
------------------------------------------------------------------
Runs the same weighted scoring formula used in the scanner app
(index.html) across every row in features.csv, compares the
predicted verdict to the real label, and reports accuracy,
precision, recall, F1-score, and a confusion matrix.

This gives you real, defensible numbers for Chapter IV instead of
one-off manual spot-checks.

Input:  data/processed/features.csv
Output: prints metrics to the terminal + saves a results CSV with
        each row's predicted score/verdict alongside its true label
"""

import csv

FEATURES_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\processed\features.csv"
RESULTS_PATH = r"C:\Users\Test\Desktop\Github Repositories\QR-Quishing-Fraud-Detection-System\data\processed\evaluation_results.csv"

# Same weights as the scanner app (index.html) — keep these two in sync manually
#
# NOTE: is_long, domain_entropy, and path_depth were deliberately excluded.
# Diagnostics showed benign vs malicious medians were nearly identical for
# all three (e.g. domain_entropy median = 2.9502 for BOTH classes; url_length
# medians were 83 vs 84 chars). A single hand-picked threshold cannot draw a
# meaningful line through data that overlaps this closely — including them
# only added noise (this was confirmed: an earlier version with entropy/path
# thresholds included produced a 96.7% false positive rate). The ML model
# can still extract some value from these via subtler statistical patterns
# a fixed rule can't access — a key, documented difference between the two
# approaches.
WEIGHTS = {
    "has_ip": 25,
    "no_https": 10,
    "has_at": 20,
    "is_shortener": 15,
    "bad_tld": 15,
    "too_many_subdomains": 10,
    "hyphen_heavy": 8,
    "brand_mismatch": 30,
    "suspicious_keyword": 12,
    "punycode": 20,
    "numeric_heavy": 8,
    "is_free_hosting": 15,
    "has_double_hyphen": 10,
}

# Matches the app's current thresholds (caution=20, danger=55)
CAUTION_THRESHOLD = 20
DANGER_THRESHOLD = 55

# Which threshold counts as "flagged risky" for accuracy purposes.
# Using CAUTION_THRESHOLD means both "caution" and "danger" verdicts
# count as a positive (risky) prediction — matches what a real user
# would treat as "don't trust this."
FLAG_THRESHOLD = CAUTION_THRESHOLD


def compute_score(row):
    score = 0
    if row.get("url_parseable", "1") == "0":
        score += 30  # matches the app's "not a well-formed URL" penalty
    for feature, weight in WEIGHTS.items():
        if row.get(feature, "0") == "1":
            score += weight
    return min(score, 100)


def main():
    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    tp = fp = tn = fn = 0
    results = []

    for row in rows:
        true_label = int(row["label"])  # 1 = malicious, 0 = benign
        score = compute_score(row)
        predicted_risky = 1 if score >= FLAG_THRESHOLD else 0

        if predicted_risky == 1 and true_label == 1:
            tp += 1
        elif predicted_risky == 1 and true_label == 0:
            fp += 1
        elif predicted_risky == 0 and true_label == 0:
            tn += 1
        else:
            fn += 1

        results.append({
            "filename": row["filename"],
            "url": row["url"],
            "true_label": true_label,
            "score": score,
            "predicted_risky": predicted_risky,
            "correct": predicted_risky == true_label,
        })

    total = len(rows)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0

    with open(RESULTS_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "url", "true_label", "score", "predicted_risky", "correct"])
        writer.writeheader()
        writer.writerows(results)

    print("=" * 50)
    print(f"Evaluated {total} rows  (flag threshold = score >= {FLAG_THRESHOLD})")
    print("=" * 50)
    print(f"True Positives  (correctly flagged malicious): {tp}")
    print(f"True Negatives  (correctly passed benign):      {tn}")
    print(f"False Positives (benign wrongly flagged):       {fp}")
    print(f"False Negatives (malicious missed):             {fn}")
    print("-" * 50)
    print(f"Accuracy:            {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1-score:            {f1:.4f}")
    print(f"False Positive Rate: {false_positive_rate:.4f}")
    print("-" * 50)
    print(f"Per-row results saved to: {RESULTS_PATH}")

    print("\nTHRESHOLD SWEEP — trading precision for recall:")
    print(f"{'Threshold':<12}{'Accuracy':<12}{'Precision':<12}{'Recall':<12}{'F1':<12}{'FPR':<10}")
    scored_rows = [(compute_score(row), int(row["label"])) for row in rows]
    for t in [40, 30, 25, 20, 15, 10, 5]:
        tp_t = sum(1 for s, lbl in scored_rows if s >= t and lbl == 1)
        fp_t = sum(1 for s, lbl in scored_rows if s >= t and lbl == 0)
        tn_t = sum(1 for s, lbl in scored_rows if s < t and lbl == 0)
        fn_t = sum(1 for s, lbl in scored_rows if s < t and lbl == 1)
        acc_t = (tp_t + tn_t) / total if total else 0
        prec_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) else 0
        rec_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) else 0
        f1_t = (2 * prec_t * rec_t / (prec_t + rec_t)) if (prec_t + rec_t) else 0
        fpr_t = fp_t / (fp_t + tn_t) if (fp_t + tn_t) else 0
        print(f"{t:<12}{acc_t:<12.4f}{prec_t:<12.4f}{rec_t:<12.4f}{f1_t:<12.4f}{fpr_t:<10.4f}")

    print("\nTip: sort evaluation_results.csv by 'correct' = False to see exactly which URLs the rule-based scorer got wrong.")


if __name__ == "__main__":
    main()
