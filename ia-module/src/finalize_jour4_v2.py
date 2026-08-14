"""
S2 Jour 4 (v2, chemin B) — Finalisation avec 15 features (+ Packet Length Std)
Seuil retenu : FPR cible 14.0%, Recall 85.12%, FPR reel 14.29%
"""

import numpy as np
import pandas as pd
import json
import tensorflow as tf
from sklearn.metrics import recall_score, precision_score, f1_score, confusion_matrix
from sklearn.utils import resample

from config import FEATURES, TARGET

DATA_DIR = "../data"
MODELS_DIR = "../models"
LOGS_DIR = "../logs"
RANDOM_STATE = 42
N_BOOTSTRAP = 30

val = pd.read_parquet(f"{DATA_DIR}/val_benign_scaled.parquet")
test = pd.read_parquet(f"{DATA_DIR}/test_mixed_scaled.parquet")
X_val = val[FEATURES].values.astype("float32")
X_test = test[FEATURES].values.astype("float32")
y_true = (test[TARGET] != "BENIGN").astype(int).values

model = tf.keras.models.load_model(f"{MODELS_DIR}/autoencoder.keras")

val_pred = model.predict(X_val, verbose=0)
val_mse = np.mean(np.square(X_val - val_pred), axis=1)
test_pred = model.predict(X_test, verbose=0)
test_mse = np.mean(np.square(X_test - test_pred), axis=1)

THRESHOLD = np.percentile(val_mse, 100 - 14.0)
y_pred = (test_mse > THRESHOLD).astype(int)

recall = recall_score(y_true, y_pred)
precision = precision_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)
tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
fpr = fp / (fp + tn)

print("=== SEUIL FINAL RETENU — Autoencoder (15 features, chemin B) ===")
print(f"Features: {FEATURES}")
print(f"Seuil (MSE): {THRESHOLD:.4f}")
print(f"Recall: {recall*100:.2f}% | Precision: {precision*100:.2f}% | F1: {f1*100:.2f}% | FPR: {fpr*100:.2f}%")
print(f"TP: {tp} | FP: {fp} | FN: {fn} | TN: {tn}")

df = test.copy()
df["predicted"] = y_pred
attack_only = df[df[TARGET] != "BENIGN"]
grouped = attack_only.groupby(TARGET).agg(total=("predicted", "count"), detected=("predicted", "sum"))
grouped["recall_pct"] = (grouped["detected"] / grouped["total"] * 100).round(2)
grouped = grouped.sort_values("total", ascending=False)
print("\nRecall par type d'attaque (seuil final, 15 features):")
print(grouped.to_string())

recalls, precisions, f1s, fprs = [], [], [], []
idx = np.arange(len(y_true))
for i in range(N_BOOTSTRAP):
    s = resample(idx, replace=True, random_state=RANDOM_STATE + i)
    yt, yp = y_true[s], y_pred[s]
    recalls.append(recall_score(yt, yp, zero_division=0))
    precisions.append(precision_score(yt, yp, zero_division=0))
    f1s.append(f1_score(yt, yp, zero_division=0))
    tn_, fp_, fn_, tp_ = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    fprs.append(fp_ / (fp_ + tn_) if (fp_ + tn_) > 0 else 0)

print(f"\nBootstrap ({N_BOOTSTRAP} iterations):")
print(f"  Recall:    {np.mean(recalls):.4f} +/- {np.std(recalls):.4f}")
print(f"  Precision: {np.mean(precisions):.4f} +/- {np.std(precisions):.4f}")
print(f"  F1:        {np.mean(f1s):.4f} +/- {np.std(f1s):.4f}")
print(f"  FPR:       {np.mean(fprs):.4f} +/- {np.std(fprs):.4f}")

n_attacks_real = int(y_true.sum())
n_alerts_model = int(y_pred.sum())
factor = n_attacks_real / n_alerts_model if n_alerts_model > 0 else float("inf")
print(f"\n[PROVISOIRE] Attaques reelles: {n_attacks_real} | Alertes levees: {n_alerts_model} | Facteur: {factor:.2f}")

final_results = {
    "version": "v2_chemin_B_15_features",
    "model_retenu": "Autoencoder",
    "features": FEATURES,
    "feature_ajoutee": "Packet Length Std",
    "seuil_mse": float(THRESHOLD),
    "fpr_cible_pct": 14.0,
    "recall": float(recall),
    "precision": float(precision),
    "f1": float(f1),
    "fpr_reel": float(fpr),
    "recall_target_cdc": 0.85,
    "conforme_recall": bool(recall >= 0.85),
    "fpr_target_cdc_max": 0.15,
    "conforme_fpr": bool(fpr <= 0.15),
    "conforme_global": bool(recall >= 0.85 and fpr <= 0.15),
    "recall_par_attaque": grouped["recall_pct"].to_dict(),
    "bootstrap": {
        "recall_mean": float(np.mean(recalls)), "recall_std": float(np.std(recalls)),
        "fpr_mean": float(np.mean(fprs)), "fpr_std": float(np.std(fprs)),
    },
    "volume_reduction_factor_provisional": factor,
    "comparaison_v1_14_features": {"recall": 0.8456, "fpr": 0.1448, "conforme_global": False},
}

with open(f"{LOGS_DIR}/jour4_final_threshold_v2.json", "w") as f:
    json.dump(final_results, f, indent=2)

print(f"\nSauvegarde: logs/jour4_final_threshold_v2.json")
