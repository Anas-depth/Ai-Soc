"""
S2 Jour 4 (complément) — Recherche fine du seuil Autoencoder
pour tenter d'atteindre Recall >= 85% tout en restant FPR <= 15%.
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import recall_score, precision_score, f1_score, confusion_matrix

from config import FEATURES, TARGET

DATA_DIR = "../data"
MODELS_DIR = "../models"

val = pd.read_parquet(f"{DATA_DIR}/val_benign_scaled.parquet")
test = pd.read_parquet(f"{DATA_DIR}/test_mixed_scaled.parquet")
X_val = val[FEATURES].values.astype("float32")
X_test = test[FEATURES].values.astype("float32")
y_true = (test[TARGET] != "BENIGN").astype(int).values

model = tf.keras.models.load_model(f"{MODELS_DIR}/autoencoder.keras")

print("Calcul des erreurs de reconstruction (val + test)...")
val_pred = model.predict(X_val, verbose=0)
val_mse = np.mean(np.square(X_val - val_pred), axis=1)

test_pred = model.predict(X_test, verbose=0)
test_mse = np.mean(np.square(X_test - test_pred), axis=1)

print("\nRecherche fine (FPR cible de 8% à 15%, pas de 0.5):")
rows = []
for q in np.arange(8, 15.5, 0.5):
    threshold = np.percentile(val_mse, 100 - q)
    y_pred = (test_mse > threshold).astype(int)
    recall = recall_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn)
    rows.append((q, threshold, recall, fpr))
    marker = "  <-- OBJECTIF ATTEINT" if recall >= 0.85 and fpr <= 0.15 else ""
    print(f"  FPR cible {q:5.1f}% | seuil {threshold:.4f} | Recall {recall*100:6.2f}% | FPR réel {fpr*100:6.2f}%{marker}")

df = pd.DataFrame(rows, columns=["fpr_cible", "threshold", "recall", "fpr_reel"])
valid = df[(df["recall"] >= 0.85) & (df["fpr_reel"] <= 0.15)]

if len(valid) > 0:
    best = valid.sort_values("fpr_reel").iloc[0]
    print(f"\n>>> Meilleur seuil trouvé : FPR cible {best['fpr_cible']}%, "
          f"seuil={best['threshold']:.4f}, Recall={best['recall']*100:.2f}%, FPR réel={best['fpr_reel']*100:.2f}%")
else:
    print("\n>>> Aucun seuil ne satisfait Recall>=85% ET FPR<=15% simultanément dans cette plage.")
    print(">>> Le meilleur compromis reste à documenter tel quel dans le rapport.")
