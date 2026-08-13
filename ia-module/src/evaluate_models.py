"""
S2 Jour 4 — Évaluation quantitative
Calibration du seuil sur val benign, évaluation sur test mixte,
Recall par type d'attaque, validation bootstrap.
"""

import numpy as np
import pandas as pd
import joblib
import json
import matplotlib.pyplot as plt
from pathlib import Path

import tensorflow as tf
from sklearn.metrics import recall_score, precision_score, f1_score, confusion_matrix
from sklearn.utils import resample

from config import FEATURES, TARGET

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

RANDOM_STATE = 42
FPR_TARGETS = [1, 3, 5, 10, 15]  # percentiles testés = FPR théorique visé sur val
N_BOOTSTRAP = 30


def load_data():
    val = pd.read_parquet(DATA_DIR / "val_benign_scaled.parquet")
    test = pd.read_parquet(DATA_DIR / "test_mixed_scaled.parquet")
    return val, test


def compute_if_scores(iforest, X):
    return iforest.score_samples(X)


def compute_ae_mse(autoencoder, X):
    pred = autoencoder.predict(X.astype("float32"), verbose=0)
    return np.mean(np.square(X.astype("float32") - pred), axis=1)


def sweep_thresholds(val_scores, test_scores, y_true, higher_is_anomaly, targets=FPR_TARGETS):
    """
    Teste plusieurs seuils calibrés sur val (percentile = FPR théorique visé).
    higher_is_anomaly=True pour AE (mse haute = anomalie)
    higher_is_anomaly=False pour IF (score bas = anomalie)
    """
    rows = []
    for q in targets:
        if higher_is_anomaly:
            threshold = np.percentile(val_scores, 100 - q)
            y_pred = (test_scores > threshold).astype(int)
        else:
            threshold = np.percentile(val_scores, q)
            y_pred = (test_scores < threshold).astype(int)

        recall = recall_score(y_true, y_pred, zero_division=0)
        precision = precision_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        rows.append({
            "fpr_cible_pct": q, "threshold": threshold, "recall": recall,
            "precision": precision, "f1": f1, "fpr_reel": fpr,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        })
    return pd.DataFrame(rows)


def recall_by_attack_type(test_df, y_pred, model_name):
    df = test_df.copy()
    df["predicted"] = y_pred
    attack_only = df[df[TARGET] != "BENIGN"]
    grouped = attack_only.groupby(TARGET).agg(
        total=("predicted", "count"),
        detected=("predicted", "sum"),
    )
    grouped["recall_pct"] = (grouped["detected"] / grouped["total"] * 100).round(2)
    grouped = grouped.sort_values("total", ascending=False)
    print(f"\n  Recall par type d'attaque ({model_name}):")
    print(grouped.to_string())
    return grouped


def bootstrap_metrics(y_true, y_pred, n_iter=N_BOOTSTRAP):
    recalls, precisions, f1s, fprs = [], [], [], []
    idx = np.arange(len(y_true))
    for i in range(n_iter):
        sample_idx = resample(idx, replace=True, random_state=RANDOM_STATE + i)
        yt, yp = y_true[sample_idx], y_pred[sample_idx]
        recalls.append(recall_score(yt, yp, zero_division=0))
        precisions.append(precision_score(yt, yp, zero_division=0))
        f1s.append(f1_score(yt, yp, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
        fprs.append(fp / (fp + tn) if (fp + tn) > 0 else 0)

    def summarize(arr):
        return f"{np.mean(arr):.4f} ± {np.std(arr):.4f} (IC95: [{np.percentile(arr,2.5):.4f}, {np.percentile(arr,97.5):.4f}])"

    print(f"    Recall:    {summarize(recalls)}")
    print(f"    Precision: {summarize(precisions)}")
    print(f"    F1:        {summarize(f1s)}")
    print(f"    FPR:       {summarize(fprs)}")


def volume_reduction_proxy(y_true, y_pred):
    n_attacks_real = int(y_true.sum())
    n_alerts_model = int(y_pred.sum())
    factor = n_attacks_real / n_alerts_model if n_alerts_model > 0 else float("inf")
    print(f"\n  [PROVISOIRE — à recalculer avec volumes Suricata réels en S3]")
    print(f"  Attaques réelles dans le test: {n_attacks_real}")
    print(f"  Alertes levées par le modèle: {n_alerts_model}")
    print(f"  Facteur (indicatif): {factor:.2f}")
    return factor


def plot_sweep(sweep_df, model_name):
    fig, ax1 = plt.subplots(figsize=(8, 4))
    ax1.plot(sweep_df["fpr_cible_pct"], sweep_df["recall"] * 100, "o-", color="steelblue", label="Recall")
    ax1.set_xlabel("FPR cible sur val (%)")
    ax1.set_ylabel("Recall (%)", color="steelblue")
    ax1.axhline(85, color="steelblue", linestyle="--", alpha=0.4, label="Cible Recall 85%")

    ax2 = ax1.twinx()
    ax2.plot(sweep_df["fpr_cible_pct"], sweep_df["fpr_reel"] * 100, "s-", color="darkorange", label="FPR réel")
    ax2.set_ylabel("FPR réel (%)", color="darkorange")
    ax2.axhline(15, color="darkorange", linestyle="--", alpha=0.4, label="Cible FPR max 15%")

    plt.title(f"{model_name} — trade-off Recall/FPR selon seuil")
    fig.tight_layout()
    plt.savefig(LOGS_DIR / f"threshold_sweep_{model_name.lower()}.png", dpi=100, bbox_inches="tight")
    plt.close()


def evaluate_model(model_name, val_scores, test_scores, higher_is_anomaly, test_df, y_true, chosen_fpr_target):
    print(f"\n{'='*60}\n=== {model_name} ===\n{'='*60}")

    sweep = sweep_thresholds(val_scores, test_scores, y_true, higher_is_anomaly)
    print("\n  Sweep de seuils (calibrés sur val benign):")
    print(sweep.to_string(index=False))
    plot_sweep(sweep, model_name)

    row = sweep[sweep["fpr_cible_pct"] == chosen_fpr_target].iloc[0]
    threshold = row["threshold"]
    if higher_is_anomaly:
        y_pred = (test_scores > threshold).astype(int)
    else:
        y_pred = (test_scores < threshold).astype(int)

    print(f"\n  >>> Seuil retenu (FPR cible {chosen_fpr_target}%): {threshold:.4f}")
    print(f"  >>> Recall global: {row['recall']*100:.2f}% | FPR réel: {row['fpr_reel']*100:.2f}% | "
          f"Precision: {row['precision']*100:.2f}% | F1: {row['f1']*100:.2f}%")

    recall_by_attack_type(test_df, y_pred, model_name)

    print(f"\n  Validation bootstrap ({N_BOOTSTRAP} itérations):")
    bootstrap_metrics(y_true.values, y_pred)

    factor = volume_reduction_proxy(y_true.values, y_pred)

    return {
        "model": model_name,
        "threshold": float(threshold),
        "fpr_cible_pct": chosen_fpr_target,
        "recall": float(row["recall"]),
        "precision": float(row["precision"]),
        "f1": float(row["f1"]),
        "fpr_reel": float(row["fpr_reel"]),
        "volume_reduction_factor_provisional": factor,
    }


def main():
    print("=== S2 Jour 4 — Évaluation quantitative ===")

    val, test = load_data()
    X_val = val[FEATURES].values
    X_test = test[FEATURES].values
    y_true = (test[TARGET] != "BENIGN").astype(int)
    print(f"Val: {X_val.shape} | Test: {X_test.shape} | Attaques dans test: {y_true.sum()}")

    iforest = joblib.load(MODELS_DIR / "isolation_forest.pkl")
    autoencoder = tf.keras.models.load_model(MODELS_DIR / "autoencoder.keras")

    if_val_scores = compute_if_scores(iforest, X_val)
    if_test_scores = compute_if_scores(iforest, X_test)

    ae_val_mse = compute_ae_mse(autoencoder, X_val)
    ae_test_mse = compute_ae_mse(autoencoder, X_test)

    CHOSEN_FPR_TARGET = 10  # ajustable après lecture du sweep

    results = []
    results.append(evaluate_model(
        "Isolation_Forest", if_val_scores, if_test_scores, False, test, y_true, CHOSEN_FPR_TARGET
    ))
    results.append(evaluate_model(
        "Autoencoder", ae_val_mse, ae_test_mse, True, test, y_true, CHOSEN_FPR_TARGET
    ))

    with open(LOGS_DIR / "jour4_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*60}")
    print("Jour 4 terminé. Résultats sauvegardés dans logs/jour4_results.json")
    print("Graphiques: logs/threshold_sweep_isolation_forest.png, logs/threshold_sweep_autoencoder.png")


if __name__ == "__main__":
    main()
