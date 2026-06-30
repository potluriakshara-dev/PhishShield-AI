"""
train_model.py  —  PhishShield AI
Trains the Random Forest classifier on phishing_dataset.csv and
evaluates it with 5-fold cross-validation.

Run:
    python generate_dataset.py   # builds phishing_dataset.csv (if not already present)
    python train_model.py        # trains + evaluates + saves phishing_model.pkl

Output:
    phishing_model.pkl — trained model, loaded automatically by url_analyzer.py
    Console report matching the metrics shown in the project deck.
"""

import pandas as pd
import time
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

DATA_PATH = "phishing_dataset.csv"
MODEL_PATH = "phishing_model.pkl"


def main():
    df = pd.read_csv(DATA_PATH)
    feature_cols = [c for c in df.columns if c not in ("label", "url")]
    X, y = df[feature_cols], df["label"]

    print(f"Dataset: {len(df)} URLs ({y.sum()} phishing, {(y==0).sum()} legitimate)")
    print(f"Features used: {feature_cols}\n")

    model = RandomForestClassifier(
        n_estimators=150, max_depth=6, min_samples_leaf=3, random_state=42
    )

    # ── 5-fold cross-validation (the honest, reported metric) ───────────────
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_pred_cv = cross_val_predict(model, X, y, cv=skf)

    acc = accuracy_score(y, y_pred_cv)
    prec = precision_score(y, y_pred_cv)
    rec = recall_score(y, y_pred_cv)
    f1 = f1_score(y, y_pred_cv)
    cm = confusion_matrix(y, y_pred_cv)

    print("=== 5-Fold Cross-Validation Results ===")
    print(f"Accuracy:  {acc*100:.1f}%")
    print(f"Precision: {prec*100:.1f}%  (of links flagged phishing, how many really were)")
    print(f"Recall:    {rec*100:.1f}%  (of real phishing links, how many were caught)")
    print(f"F1 Score:  {f1*100:.1f}%")
    print(f"Confusion Matrix:\n{cm}")
    print(f"  True Negatives  (safe, correctly passed):  {cm[0][0]}")
    print(f"  False Positives (safe, wrongly flagged):   {cm[0][1]}")
    print(f"  False Negatives (phishing, missed):        {cm[1][0]}")
    print(f"  True Positives  (phishing, correctly caught): {cm[1][1]}\n")

    # ── Train final model on ALL data for production use ────────────────────
    model.fit(X, y)

    # ── Inference timing benchmark ───────────────────────────────────────────
    X_sample = X.iloc[[0]]
    start = time.time()
    for _ in range(200):
        model.predict(X_sample)
    avg_ms = (time.time() - start) / 200 * 1000
    print(f"Average inference time: {avg_ms:.2f} ms per URL\n")

    # ── Feature importance ────────────────────────────────────────────────────
    importances = pd.Series(model.feature_importances_, index=feature_cols)
    importances = importances.sort_values(ascending=False)
    print("Top predictive features:")
    for name, val in importances.head(6).items():
        print(f"  {name}: {val*100:.1f}%")

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
