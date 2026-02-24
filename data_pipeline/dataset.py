#truncation
#keeps only first 256 character for android simulation
#transoformers have fixed token of 512 character
# data_pipeline/dataset.py

import pandas as pd
from pathlib import Path

#path to dataset
BASE_DIR = Path("C:/Users/ritam/Desktop/FishNet_Prototype/data/merged_dataset.parquet")

#cleaning function
def clean_dataset(df):
    required_columns = {"body", "label"}
    missing = required_columns.difference(df.columns)
    if missing:
        raise KeyError(f"Missing required column(s): {', '.join(sorted(missing))}")

    # Drop nulls
    df = df.dropna(subset=["body"]).copy()

    # Convert to string
    df["body"] = df["body"].astype(str)

    # Remove very short rows
    df = df[df["body"].str.len() > 5]

    # Remove extra whitespace
    df["body"] = df["body"].str.replace(r"\s+", " ", regex=True).str.strip()

    # Truncate to notification-style
    df["body"] = df["body"].str.slice(0, 256)

    # Remove duplicates
    df = df.drop_duplicates(subset=["body"])

    return df
#load+prepare dataset 
def load_dataset():
    if not BASE_DIR.exists():
        raise FileNotFoundError(f"Dataset not found at {BASE_DIR}")

    print("Loading dataset from:", BASE_DIR)

    df = pd.read_parquet(BASE_DIR)

    print("Original shape:", df.shape)

    df = clean_dataset(df)

    print("After cleaning:", df.shape)
    print("\nClass distribution:")
    print(df["label"].value_counts())

    return df
#main function
if __name__ == "__main__":
    df = load_dataset()

    print("\nFinal dataset ready.")
    print(df.head())
