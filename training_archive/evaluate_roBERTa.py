import torch
import numpy as np
import sys
import os
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    log_loss,
    matthews_corrcoef,
    roc_auc_score
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data_pipeline.dataset import load_dataset

# -----------------------------
# CONFIG
# -----------------------------
MODEL_NAME = "roberta-base"
MODEL_DIR = PROJECT_ROOT / "models" / "roberta_model"
MAX_LENGTH = 128
BATCH_SIZE = 8   # small batch to avoid CUDA OOM
EVAL_MAX_SAMPLES = int(os.getenv("EVAL_MAX_SAMPLES", "0"))

checkpoint_paths = sorted(
    [p for p in MODEL_DIR.glob("checkpoint-*") if p.is_dir()],
    key=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else -1
)
MODEL_PATH = checkpoint_paths[-1] if checkpoint_paths else MODEL_DIR

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# -----------------------------
# LOAD DATA
# -----------------------------
df = load_dataset()

# Normalize labels exactly as training
label_values = sorted(df["label"].unique().tolist())
label2id = {label: idx for idx, label in enumerate(label_values)}
df["label"] = df["label"].map(label2id).astype("int64")

# Recreate split (same random_state!)
_, temp_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df["label"],
    random_state=42
)

_, test_df = train_test_split(
    temp_df,
    test_size=0.5,
    stratify=temp_df["label"],
    random_state=42
)
if EVAL_MAX_SAMPLES > 0:
    test_df = test_df.sample(n=min(EVAL_MAX_SAMPLES, len(test_df)), random_state=42)

test_dataset = Dataset.from_pandas(test_df, preserve_index=False)

# -----------------------------
# TOKENIZE
# -----------------------------
try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
except OSError:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(
        batch["body"],
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH
    )

test_dataset = test_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.remove_columns(["body"])
test_dataset = test_dataset.rename_column("label", "labels")
test_dataset.set_format("torch")

# -----------------------------
# LOAD MODEL
# -----------------------------
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.to(device)
model.eval()

# -----------------------------
# INFERENCE
# -----------------------------
all_logits = []
all_labels = []

with torch.no_grad():
    for i in range(0, len(test_dataset), BATCH_SIZE):
        batch = test_dataset[i:i+BATCH_SIZE]

        inputs = {
            "input_ids": batch["input_ids"].to(device),
            "attention_mask": batch["attention_mask"].to(device),
        }

        outputs = model(**inputs)
        logits = outputs.logits.cpu().numpy()

        all_logits.append(logits)
        all_labels.append(batch["labels"].cpu().numpy())

logits = np.vstack(all_logits)
labels = np.concatenate(all_labels)

probs = torch.nn.functional.softmax(
    torch.tensor(logits), dim=1
).numpy()

preds = np.argmax(probs, axis=1)

# -----------------------------
# METRICS
# -----------------------------
accuracy = accuracy_score(labels, preds)
macro_f1 = f1_score(labels, preds, average="macro")
ll = log_loss(labels, probs)
mcc = matthews_corrcoef(labels, preds)
roc_auc = roc_auc_score(labels, probs, multi_class="ovr")

print("\n===== Test Evaluation (Best Checkpoint) =====")
print(f"Accuracy: {accuracy:.4f}")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Log Loss: {ll:.4f}")
print(f"MCC: {mcc:.4f}")
print(f"Macro ROC-AUC: {roc_auc:.4f}")
