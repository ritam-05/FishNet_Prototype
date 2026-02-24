import os
import sys
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    log_loss,
    matthews_corrcoef,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from transformers import AutoModelForSequenceClassification, AutoTokenizer

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data_pipeline.dataset import load_dataset


MODEL_NAME = os.getenv("MODEL_NAME", "google/electra-small-discriminator")
MODEL_DIR = PROJECT_ROOT / "models" / "electra_small_model"
MAX_LENGTH = int(os.getenv("EVAL_MAX_LENGTH", "128"))
BATCH_SIZE = int(os.getenv("EVAL_BATCH_SIZE", "16"))
EVAL_MAX_SAMPLES = int(os.getenv("EVAL_MAX_SAMPLES", "0"))

checkpoint_paths = sorted(
    [p for p in MODEL_DIR.glob("checkpoint-*") if p.is_dir()],
    key=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else -1,
)
MODEL_PATH = checkpoint_paths[-1] if checkpoint_paths else MODEL_DIR

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load and recreate test split exactly like training scripts.
df = load_dataset()
label_values = sorted(df["label"].unique().tolist())
label2id = {label: idx for idx, label in enumerate(label_values)}
df["label"] = df["label"].map(label2id).astype("int64")

_, temp_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df["label"],
    random_state=42,
)
_, test_df = train_test_split(
    temp_df,
    test_size=0.5,
    stratify=temp_df["label"],
    random_state=42,
)
if EVAL_MAX_SAMPLES > 0:
    test_df = test_df.sample(n=min(EVAL_MAX_SAMPLES, len(test_df)), random_state=42)

test_dataset = Dataset.from_pandas(test_df, preserve_index=False)

try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
except OSError:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


def tokenize(batch):
    return tokenizer(
        batch["body"],
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
    )


test_dataset = test_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.remove_columns(["body"])
test_dataset = test_dataset.rename_column("label", "labels")
test_dataset.set_format("torch")

model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH).to(device)
model.eval()

all_logits = []
all_labels = []

with torch.no_grad():
    for i in range(0, len(test_dataset), BATCH_SIZE):
        batch = test_dataset[i : i + BATCH_SIZE]
        inputs = {
            "input_ids": batch["input_ids"].to(device),
            "attention_mask": batch["attention_mask"].to(device),
        }
        outputs = model(**inputs)
        all_logits.append(outputs.logits.detach().cpu().numpy())
        all_labels.append(batch["labels"].cpu().numpy())

logits = np.vstack(all_logits)
labels = np.concatenate(all_labels)
probs = torch.nn.functional.softmax(torch.tensor(logits), dim=1).numpy()
preds = np.argmax(probs, axis=1)

accuracy = accuracy_score(labels, preds)
macro_f1 = f1_score(labels, preds, average="macro")
ll = log_loss(labels, probs)
mcc = matthews_corrcoef(labels, preds)
roc_auc = roc_auc_score(labels, probs, multi_class="ovr")

print("\n===== ELECTRA Test Evaluation =====")
print(f"Model path: {MODEL_PATH}")
print(f"Samples: {len(test_dataset)}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Log Loss: {ll:.4f}")
print(f"MCC: {mcc:.4f}")
print(f"Macro ROC-AUC: {roc_auc:.4f}")