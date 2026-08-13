"""
S2 Jour 4 (extension) — Ensemble IF + Autoencoder (règle OR)
Calibration des 2 seuils EXCLUSIVEMENT sur le FPR du val benign (jamais sur le test).
Évaluation finale unique sur le test, sans reconsultation.
"""

import numpy as np
import pandas as pd
import joblib
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
MAX_FPR_BUDGET = 0.15  # cible du cahier des charges

print("=== Ensemble Isolation Forest + Autoencoder (OR) ===\n")

val = pd.read_parquet(f"{DATA_DIR}/val_benign_scaled.parquet")
test = pd.read_parquet(f"{DATA_DIR}/test_mixed_scaled.parquet")
X_val = val[FEATURES].values
X_test = test[FEATURES].values
X_val_f32 = X_val.astype("float32")
X_test_f32 = X_test.astype("float32")
y_true = (test[TARGET] != "BENIGN").astype(int).values

print("[1/4] Chargement des modèles et calcul des scores...")
iforest = joblib.load(f"{MODELS_DIR}/isolation_forest.pkl")
autoencoder = tf.keras.models.load_model(f"{MODELS_DIR}/autoencoder.keras")

if_val_scores = iforest.score_samples(X_val)
if_test_scores = iforest.score_samples(X_test)

ae_val_pred = autoencoder.predict(X_val_f32, verbose=0)
ae_val_mse = np.mean(np.square(X_val_f32 - ae_val_pred), axis=1)
ae_test_pred = autoencoder.predict(X_test_f32, verbose=0)
ae_test_mse = np.mean(np.square(X_test_f32 - ae_test_pred), axis=1)

print("[2/4] Grid search sur le VAL uniquement (jamais le test) pour caler les 2 seuils...")
# Budget principalement donné à l'AE (modèle le plus performant seul),
# IF ajoute un complément ciblé sur les patterns qu'il isole bien (ex. PortScan, Infiltration).
IF_FPR_CANDIDATES = [0.5, 1.0, 1.5, 2.0, 3.0]   # petit budget pour IF
AE_FPR_CANDIDATES = np.arange(5.0, 15.5, 0.5)    # gros budget pour AE

results_grid = []
for p_if in IF_FPR_CANDIDATES:
    thresh_if = np.percentile(if_val_scores, p_if)  # score bas = anomalie
    for p_ae in AE_FPR_CANDIDATES:
        thresh_ae = np.percentile(ae_val_mse, 100 - p_ae)  # mse haute = anomalie
        val_flag_if = if_val_scores < thresh_if
        val_flag_ae = ae_val_mse > thresh_ae
        val_union_fpr = (val_flag_if | val_flag_ae).mean()
        if val_union_fpr <= MAX_FPR_BUDGET:
            results_grid.append((p_if, p_ae, thresh_if, thresh_ae, val_union_fpr))

grid_df = pd.DataFrame(results_grid, columns=["p_if", "p_ae", "thresh_if", "thresh_ae", "val_fpr"])
# On choisit la combinaison qui utilise le budget FPR au maximum (le plus proche de 15% sans dépasser)
best = grid_df.sort_values("val_fpr", ascending=False).iloc[0]

print(f"\n  Combinaison retenue (budget val FPR max utilisé):")
print(f"    IF  -> FPR cible {best['p_if']}% | seuil = {best['thresh_if']:.4f}")
print(f"    AE  -> FPR cible {best['p_ae']}% | seuil = {best['thresh_ae']:.4f}")
print(f"    FPR combiné mesuré sur val: {best['val_fpr']*100:.2f}%")

print("\n[3/4] Évaluation UNIQUE sur le test (pas de reconsultation pour ajuster les seuils)...")
test_flag_if = if_test_scores < best["thresh_if"]
test_flag_ae = ae_test_mse > best["thresh_ae"]
y_pred = (test_flag_if | test_flag_ae).astype(int)

recall = recall_score(y_true, y_pred)
precision = precision_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)
tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
fpr = fp / (fp + tn)

print(f"\n  >>> Recall global: {recall*100:.2f}%")
print(f"  >>> Precision: {precision*100:.2f}%")
print(f"  >>> F1: {f1*100:.2f}%")
print(f"  >>> FPR réel (test): {fpr*100:.2f}%")
print(f"  >>> TP: {tp} | FP: {fp} | FN: {fn} | TN: {tn}")

conforme = recall >= 0.85 and fpr <= 0.15
print(f"\n  {'>>> CONFORME au cahier des charges (Recall>=85%, FPR<=15%)' if conforme else '>>> Toujours sous la cible Recall, malgré l ensemble'}")

print("\n[4/4] Recall par type d'attaque + bootstrap...")
df = test.copy()
df["predicted"] = y_pred
attack_only = df[df[TARGET] != "BENIGN"]
grouped = attack_only.groupby(TARGET).agg(total=("predicted", "count"), detected=("predicted", "sum"))
grouped["recall_pct"] = (grouped["detected"] / grouped["total"] * 100).round(2)
grouped = grouped.sort_values("total", ascending=False)
print("\n  Recall par type d'attaque (ensemble):")
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

print(f"\n  Bootstrap ({N_BOOTSTRAP} itérations):")
print(f"    Recall:    {np.mean(recalls):.4f} ± {np.std(recalls):.4f}")
print(f"    Precision: {np.mean(precisions):.4f} ± {np.std(precisions):.4f}")
print(f"    F1:        {np.mean(f1s):.4f} ± {np.std(f1s):.4f}")
print(f"    FPR:       {np.mean(fprs):.4f} ± {np.std(fprs):.4f}")

n_attacks_real = int(y_true.sum())
n_alerts_model = int(y_pred.sum())
factor = n_attacks_real / n_alerts_model if n_alerts_model > 0 else float("inf")
print(f"\n  [PROVISOIRE] Attaques réelles: {n_attacks_real} | Alertes levées: {n_alerts_model} | Facteur: {factor:.2f}")

final_results = {
    "model_retenu": "Ensemble_IF_OR_AE",
    "threshold_if": float(best["thresh_if"]),
    "threshold_ae": float(best["thresh_ae"]),
    "fpr_cible_if_pct": float(best["p_if"]),
    "fpr_cible_ae_pct": float(best["p_ae"]),
    "val_fpr_combine": float(best["val_fpr"]),
    "recall": float(recall),
    "precision": float(precision),
    "f1": float(f1),
    "fpr_reel": float(fpr),
    "conforme_cahier_des_charges": bool(conforme),
    "recall_par_attaque": grouped["recall_pct"].to_dict(),
    "bootstrap": {
        "recall_mean": float(np.mean(recalls)), "recall_std": float(np.std(recalls)),
        "fpr_mean": float(np.mean(fprs)), "fpr_std": float(np.std(fprs)),
    },
    "volume_reduction_factor_provisional": factor,
}

with open(f"{LOGS_DIR}/jour4_ensemble_results.json", "w") as f:
    json.dump(final_results, f, indent=2)

print(f"\nSauvegardé: logs/jour4_ensemble_results.json")
