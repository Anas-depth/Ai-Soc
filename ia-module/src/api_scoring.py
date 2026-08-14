# src/api_scoring.py
"""
Service de scoring d'anomalie - SOC-IA
Modèle retenu (S2 Jour 4, corrigé Jour 5) : Autoencoder, 15 features, seuil MSE = 0.2512
Pipeline d'inférence identique au pipeline d'entraînement (src/preprocessing.py) :
imputation (NaN/inf rejetés) -> winsorization IQR -> log1p (shift persisté) -> scaling -> MSE
"""
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import joblib
import tensorflow as tf

from src.config import FEATURES

app = FastAPI(title="SOC-IA Scoring Service")

# --- Chargement des artefacts (une seule fois, au démarrage) ---
scaler = joblib.load("models/scaler.pkl")
iqr_bounds = joblib.load("models/iqr_bounds.pkl")
skewed_cols = joblib.load("models/skewed_cols.pkl")
log_shifts = joblib.load("models/log_shifts.pkl")
autoencoder = tf.keras.models.load_model("models/autoencoder.keras")

# Seuil retenu au Jour 4, recalibré au Jour 5 après correction du bug log1p
THRESHOLD_MSE = 0.2512


class FlowFeatures(BaseModel):
    features: list[float]  # ordre = FEATURES défini dans config.py (15 valeurs)


def preprocess(raw_values: list[float]) -> np.ndarray:
    """Reproduit exactement les étapes 2.3 à 2.4 de preprocessing.py, dans le même ordre."""
    x = dict(zip(FEATURES, raw_values))

    # Étape 1 - rejet des valeurs non finies (pas d'imputation en inférence, cf. décision Jour 5)
    for col, val in x.items():
        if not np.isfinite(val):
            raise ValueError(f"Valeur non finie pour '{col}': {val}")

    # Étape 2 - winsorization IQR (bornes calculées sur train benign, Jour 2)
    for col in FEATURES:
        if col in iqr_bounds:
            lower, upper = iqr_bounds[col]
            x[col] = min(max(x[col], lower), upper)

    # Étape 3 - log1p avec shift persisté (train benign uniquement, fix Jour 5)
    for col in skewed_cols:
        x[col] = np.log1p(x[col] + log_shifts[col])

    # Étape 4 - mise en array dans l'ordre exact de FEATURES
    return np.array([[x[col] for col in FEATURES]], dtype="float32")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "n_features": len(FEATURES),
        "threshold_mse": THRESHOLD_MSE,
        "skewed_cols": skewed_cols,
    }


@app.post("/score")
def score_flow(flow: FlowFeatures):
    if len(flow.features) != len(FEATURES):
        return {
            "error": f"Nombre de features incorrect : {len(flow.features)} reçues, {len(FEATURES)} attendues.",
            "expected_order": FEATURES,
        }

    try:
        X_pre = preprocess(flow.features)
    except ValueError as e:
        return {"error": str(e)}

    X_scaled = scaler.transform(X_pre)

    reconstruction = autoencoder.predict(X_scaled, verbose=0)
    mse = float(np.mean(np.square(X_scaled - reconstruction)))

    is_anomaly = mse > THRESHOLD_MSE

    return {
        "anomaly_score": mse,
        "threshold": THRESHOLD_MSE,
        "is_anomaly": is_anomaly,
        "severity": "HIGH" if mse > THRESHOLD_MSE * 2 else ("MEDIUM" if is_anomaly else "LOW"),
    }
