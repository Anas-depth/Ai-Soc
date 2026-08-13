"""
S2 Jour 3 — Entraînement des modèles d'anomalie
Isolation Forest (principal) + Autoencoder (comparaison)
Entraînés exclusivement sur benign (train_benign_scaled.parquet)
"""

import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from pathlib import Path

from sklearn.ensemble import IsolationForest

import tensorflow as tf
from tensorflow.keras import layers, Model
from tensorflow.keras.callbacks import EarlyStopping

from config import FEATURES

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

RANDOM_STATE = 42


def load_sets():
    train = pd.read_parquet(DATA_DIR / "train_benign_scaled.parquet")
    val = pd.read_parquet(DATA_DIR / "val_benign_scaled.parquet")
    return train[FEATURES], val[FEATURES]


def train_isolation_forest(X_train, X_val):
    print("\n=== Isolation Forest ===")
    iforest = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        max_samples="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    iforest.fit(X_train)
    print("  Entraînement terminé.")

    train_scores = iforest.score_samples(X_train)
    val_scores = iforest.score_samples(X_val)
    print(f"  Score moyen train: {train_scores.mean():.4f} | val: {val_scores.mean():.4f}")

    joblib.dump(iforest, MODELS_DIR / "isolation_forest.pkl")

    plt.figure(figsize=(8, 4))
    plt.hist(val_scores, bins=100, color="steelblue")
    plt.title("Isolation Forest — distribution des scores (val benign)")
    plt.xlabel("score_samples (plus négatif = plus anormal)")
    plt.savefig(LOGS_DIR / "if_score_distribution.png", dpi=100, bbox_inches="tight")
    plt.close()
    print(f"  Modèle sauvegardé: models/isolation_forest.pkl")
    print(f"  Histogramme sauvegardé: logs/if_score_distribution.png")

    return iforest


def build_autoencoder(input_dim):
    inputs = layers.Input(shape=(input_dim,))
    x = layers.Dense(8, activation="relu")(inputs)
    x = layers.Dense(4, activation="relu")(x)
    bottleneck = layers.Dense(4, activation="relu", name="bottleneck")(x)
    x = layers.Dense(4, activation="relu")(bottleneck)
    x = layers.Dense(8, activation="relu")(x)
    outputs = layers.Dense(input_dim, activation="linear")(x)

    autoencoder = Model(inputs, outputs, name="autoencoder")
    autoencoder.compile(optimizer="adam", loss="mse")
    return autoencoder


def train_autoencoder(X_train, X_val):
    print("\n=== Autoencoder ===")
    X_train_np = X_train.values.astype("float32")
    X_val_np = X_val.values.astype("float32")

    autoencoder = build_autoencoder(input_dim=X_train_np.shape[1])
    autoencoder.summary()

    early_stop = EarlyStopping(
        monitor="val_loss", patience=5, restore_best_weights=True
    )

    history = autoencoder.fit(
        X_train_np, X_train_np,
        validation_data=(X_val_np, X_val_np),
        epochs=50,
        batch_size=256,
        shuffle=True,
        callbacks=[early_stop],
        verbose=2,
    )

    autoencoder.save(MODELS_DIR / "autoencoder.keras")
    print(f"  Modèle sauvegardé: models/autoencoder.keras")

    plt.figure(figsize=(8, 4))
    plt.plot(history.history["loss"], label="train_loss")
    plt.plot(history.history["val_loss"], label="val_loss")
    plt.title("Autoencoder — courbe d'apprentissage")
    plt.xlabel("epoch")
    plt.ylabel("MSE")
    plt.legend()
    plt.savefig(LOGS_DIR / "ae_loss_curve.png", dpi=100, bbox_inches="tight")
    plt.close()
    print(f"  Courbe sauvegardée: logs/ae_loss_curve.png")

    val_pred = autoencoder.predict(X_val_np, verbose=0)
    val_mse = np.mean(np.square(X_val_np - val_pred), axis=1)
    print(f"  Erreur de reconstruction moyenne (val): {val_mse.mean():.5f}")

    plt.figure(figsize=(8, 4))
    plt.hist(val_mse, bins=100, color="darkorange")
    plt.title("Autoencoder — distribution erreur de reconstruction (val benign)")
    plt.xlabel("MSE")
    plt.savefig(LOGS_DIR / "ae_reconstruction_error_distribution.png", dpi=100, bbox_inches="tight")
    plt.close()
    print(f"  Histogramme sauvegardé: logs/ae_reconstruction_error_distribution.png")

    return autoencoder


def main():
    print("=== S2 Jour 3 — Entraînement des modèles ===")
    MODELS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    X_train, X_val = load_sets()
    print(f"Train: {X_train.shape} | Val: {X_val.shape}")

    train_isolation_forest(X_train, X_val)
    train_autoencoder(X_train, X_val)

    print("\nJour 3 terminé. Modèles prêts pour l'évaluation du Jour 4.")


if __name__ == "__main__":
    main()
