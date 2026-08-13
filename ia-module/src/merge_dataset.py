import pandas as pd
import glob
import os

RAW_DIR = os.path.expanduser("~/Documents/soc-project/datasets/cicids2017")
OUT_PATH = os.path.expanduser("~/Documents/soc-project/ia-module/data/cicids2017_full.parquet")

files = glob.glob(os.path.join(RAW_DIR, "*.csv"))
print(f"{len(files)} fichiers CSV trouvés")
for f in files:
    print(" -", os.path.basename(f))

dfs = []
for f in files:
    print(f"Lecture de {os.path.basename(f)}...")
    df = pd.read_csv(f, encoding='latin1', low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    dfs.append(df)

full_df = pd.concat(dfs, ignore_index=True)
print(f"\nShape finale : {full_df.shape}")
print(full_df['Label'].value_counts())

full_df.to_parquet(OUT_PATH, index=False)
print(f"\nSauvegardé dans {OUT_PATH}")
