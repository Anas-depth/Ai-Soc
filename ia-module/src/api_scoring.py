# src/api_scoring.py
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
import tensorflow as tf

from src.config import FEATURES

app = FastAPI(title="SOC-IA Scoring Service")

scaler = joblib.load("models/scaler.pkl")
autoencoder = tf.keras.models.load_model("models/autoencoder.keras")

# Seuil retenu au Jour 4 (FPR cible 14,0% sur val benign)
THRESHOLD_MSE = 0.2515

class FlowFeatures(BaseModel):
    features: list[float]  # ordre = FEATURES défini dans config.py (15 valeurs)

@app.get("/health")
def health():
    return {"status": "ok", "n_features": len(FEATURES), "threshold": THRESHOLD_MSE}

@app.post("/score")
def score_flow(flow: FlowFeatures):
    if len(flow.features) != len(FEATURES):
        return {
            "error": f"Nombre de features incorrect : {len(flow.features)} reçues, {len(FEATURES)} attendues.",
            "expected_order": FEATURES
        }

    X = np.array(flow.features).reshape(1, -1)
    X_scaled = scaler.transform(X)

    reconstruction = autoencoder.predict(X_scaled, verbose=0)
    mse = float(np.mean(np.square(X_scaled - reconstruction)))

    is_anomaly = mse > THRESHOLD_MSE

    return {
        "anomaly_score": mse,
        "threshold": THRESHOLD_MSE,
        "is_anomaly": is_anomaly,
        "severity": "HIGH" if mse > THRESHOLD_MSE * 2 else ("MEDIUM" if is_anomaly else "LOW")
    }
