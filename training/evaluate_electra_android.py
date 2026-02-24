import os
import sys
import time
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
MODEL_DIR = PROJECT_ROOT / "models" / "electra_small_android"
MAX_LENGTH = int(os.getenv("EVAL_MAX_LENGTH", "64"))
EVAL_MAX_SAMPLES = int(os.getenv("EVAL_MAX_SAMPLES", "0"))
LATENCY_RUNS = int(os.getenv("APP_LATENCY_RUNS", "30"))
# Default is NOT forcing CPU. Set APP_FORCE_CPU=1 only when you want CPU-only timing.
FORCE_CPU = os.getenv("APP_FORCE_CPU", "0") == "1"

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        f"Model directory does not exist: {MODEL_DIR}. "
        "Run retraining first to export the Android model."
    )

device = torch.device("cpu" if FORCE_CPU else ("cuda" if torch.cuda.is_available() else "cpu"))
default_bs = 128 if device.type == "cuda" else 32
BATCH_SIZE = int(os.getenv("EVAL_BATCH_SIZE", str(default_bs)))

# Load and recreate test split exactly like training scripts.
dataset_start = time.perf_counter()
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
dataset_prepare_s = time.perf_counter() - dataset_start

test_dataset = Dataset.from_pandas(test_df, preserve_index=False)

tokenizer_start = time.perf_counter()
try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    tokenizer_source = MODEL_DIR
except OSError:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer_source = MODEL_NAME
tokenizer_load_s = time.perf_counter() - tokenizer_start


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
tokenize_s = time.perf_counter() - tokenizer_start - tokenizer_load_s

load_start = time.perf_counter()
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
model.eval()
model_load_s = time.perf_counter() - load_start

# Timing estimate for local offline app usage (cold + steady-state single text inference).
sample_text = str(test_df.iloc[0]["body"]) if len(test_df) > 0 else "offline inference latency probe"
single_inputs = tokenizer(
    sample_text,
    padding="max_length",
    truncation=True,
    max_length=MAX_LENGTH,
    return_tensors="pt",
)
single_inputs = {k: v.to(device) for k, v in single_inputs.items()}

with torch.no_grad():
    cold_start = time.perf_counter()
    _ = model(**single_inputs)
    if device.type == "cuda":
        torch.cuda.synchronize()
    cold_infer_s = time.perf_counter() - cold_start

latencies_ms = []
with torch.no_grad():
    for _ in range(max(1, LATENCY_RUNS)):
        t0 = time.perf_counter()
        _ = model(**single_inputs)
        if device.type == "cuda":
            torch.cuda.synchronize()
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

avg_single_ms = float(np.mean(latencies_ms))
p95_single_ms = float(np.percentile(latencies_ms, 95))

all_logits = []
all_labels = []
eval_start = time.perf_counter()
num_batches = (len(test_dataset) + BATCH_SIZE - 1) // BATCH_SIZE

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
        if ((i // BATCH_SIZE) + 1) % 100 == 0:
            done = (i // BATCH_SIZE) + 1
            elapsed = time.perf_counter() - eval_start
            print(
                f"[eval] batch {done}/{num_batches} | "
                f"elapsed {elapsed:.1f}s | "
                f"avg/batch {elapsed / done:.3f}s"
            )

eval_s = time.perf_counter() - eval_start

logits = np.vstack(all_logits)
labels = np.concatenate(all_labels)
probs = torch.nn.functional.softmax(torch.tensor(logits), dim=1).numpy()
preds = np.argmax(probs, axis=1)

accuracy = accuracy_score(labels, preds)
macro_f1 = f1_score(labels, preds, average="macro")
ll = log_loss(labels, probs)
mcc = matthews_corrcoef(labels, preds)
roc_auc = roc_auc_score(labels, probs, multi_class="ovr")

print("\n===== ELECTRA Android Test Evaluation =====")
print(f"Model path: {MODEL_DIR}")
print(f"Tokenizer source: {tokenizer_source}")
print(f"Device used: {device}")
print(f"Batch size: {BATCH_SIZE}")
print(f"Samples: {len(test_dataset)}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Log Loss: {ll:.4f}")
print(f"MCC: {mcc:.4f}")
print(f"Macro ROC-AUC: {roc_auc:.4f}")

print("\n===== Offline Local App Timing Estimate =====")
print(f"Dataset prep time: {dataset_prepare_s:.3f}s")
print(f"Tokenization time: {tokenize_s:.3f}s")
print(f"Tokenizer load time: {tokenizer_load_s:.3f}s")
print(f"Model load time: {model_load_s:.3f}s")
print(f"Evaluation forward-pass time: {eval_s:.3f}s")
print(f"First (cold) inference time: {cold_infer_s * 1000.0:.2f}ms")
print(f"Average single inference ({max(1, LATENCY_RUNS)} runs): {avg_single_ms:.2f}ms")
print(f"P95 single inference: {p95_single_ms:.2f}ms")
print(f"Estimated app startup (tokenizer + model load): {tokenizer_load_s + model_load_s:.3f}s")
