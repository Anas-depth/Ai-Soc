"""
Pipeline de préparation des données - S2 Jour 2
Anti-fuite stricte : médiane, bornes IQR, skew et scaler
sont calculés EXCLUSIVEMENT sur le train benign.
"""

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config import FEATURES, TARGET

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

INPUT_PARQUET = DATA_DIR / "cicids2017_full.parquet"
RANDOM_STATE = 42


def load_data():
    return pd.read_parquet(INPUT_PARQUET)


def clean_and_impute(df):
    df = df.copy()
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)
    df[FEATURES] = df[FEATURES].fillna(df[FEATURES].median())
    return df




def split_benign_attack(df):
    benign = df[df[TARGET] == 'BENIGN'].copy()
    attack = df[df[TARGET] != 'BENIGN'].copy()
    return benign, attack


def compute_iqr_bounds(train_df, cols, k=1.5):
    bounds = {}
    skipped = []
    for col in cols:
        q1, q3 = train_df[col].quantile([0.25, 0.75])
        iqr = q3 - q1
        if iqr == 0:
            skipped.append(col)
            continue
        bounds[col] = (q1 - k * iqr, q3 + k * iqr)
    if skipped:
        print(f"  Colonnes exclues du winsorizing (IQR=0, quasi-binaires) : {skipped}")
    return bounds


def apply_winsorization(df, bounds):
    df = df.copy()
    for col, (lower, upper) in bounds.items():
        df[col] = df[col].clip(lower=lower, upper=upper)
    return df


def get_skewed_features(train_df, cols, threshold=1.0):
    skews = train_df[cols].skew()
    return skews[skews.abs() > threshold].index.tolist(), skews


def apply_log1p(df, skewed_cols):
    df = df.copy()
    for col in skewed_cols:
        min_val = df[col].min()
        shift = abs(min_val) + 1 if min_val < 0 else 0
        df[col] = np.log1p(df[col] + shift)
    return df


def main():
    print("=== S2 Jour 2 — Pipeline anti-fuite ===\n")

    print("[1/6] Chargement du dataset...")
    df = load_data()
    print(f"  Shape initiale: {df.shape}")

    print("[2/6] Nettoyage inf -> NaN -> imputation médiane...")
    df = clean_and_impute(df)
    print(f"  Inf restants: {np.isinf(df[FEATURES]).sum().sum()} | "
          f"NaN restants: {df[FEATURES].isna().sum().sum()}")

    print("[3/6] Split BENIGN vs ATTACK...")
    benign, attack = split_benign_attack(df)
    print(f"  Benign: {len(benign)} | Attack: {len(attack)}")

    print("[4/6] Split benign : train(80%) / val(10%) / test_benign(10%)...")
    train_benign, holdout_benign = train_test_split(
        benign, test_size=0.2, random_state=RANDOM_STATE, shuffle=True)
    val_benign, test_benign = train_test_split(
        holdout_benign, test_size=0.5, random_state=RANDOM_STATE, shuffle=True)
    print(f"  Train: {len(train_benign)} | Val: {len(val_benign)} | Test_benign: {len(test_benign)}")

    test_mixed = pd.concat([test_benign, attack], axis=0)
    test_mixed = test_mixed.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    print(f"  Test mixte: {len(test_mixed)} ({len(test_benign)} benign + {len(attack)} attack)")

    print("[5/6] Winsorization IQR (bornes = train benign uniquement)...")
    iqr_bounds = compute_iqr_bounds(train_benign, FEATURES)
    train_w = apply_winsorization(train_benign, iqr_bounds)
    val_w = apply_winsorization(val_benign, iqr_bounds)
    test_w = apply_winsorization(test_mixed, iqr_bounds)

    skewed_cols, skew_values = get_skewed_features(train_w, FEATURES)
    print(f"  Features skewed (|skew| > 1.0): {skewed_cols}")
    train_log = apply_log1p(train_w, skewed_cols)
    val_log = apply_log1p(val_w, skewed_cols)
    test_log = apply_log1p(test_w, skewed_cols)

    print("[6/6] Standardisation (fit = train benign uniquement)...")
    scaler = StandardScaler()
    train_log[FEATURES] = scaler.fit_transform(train_log[FEATURES])
    val_log[FEATURES] = scaler.transform(val_log[FEATURES])
    test_log[FEATURES] = scaler.transform(test_log[FEATURES])

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(iqr_bounds, MODELS_DIR / "iqr_bounds.pkl")
    joblib.dump(skewed_cols, MODELS_DIR / "skewed_cols.pkl")

    train_log.to_parquet(DATA_DIR / "train_benign_scaled.parquet")
    val_log.to_parquet(DATA_DIR / "val_benign_scaled.parquet")
    test_log.to_parquet(DATA_DIR / "test_mixed_scaled.parquet")

    print("\nTerminé. Fichiers sauvegardés dans data/ et models/.")


if __name__ == "__main__":
    main()
