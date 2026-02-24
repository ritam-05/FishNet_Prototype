import sys
import os
import gc
import torch
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, f1_score
from datasets import Dataset

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
import torch.nn as nn

#config
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = "google/electra-small-discriminator"
OUTPUT_DIR = PROJECT_ROOT / "models" / "electra_small_model"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
if device.type == "cuda":
    # Faster tensor-core matmul on supported NVIDIA GPUs.
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

TRAIN_BS = int(os.getenv("ELECTRA_TRAIN_BS", "16"))
EVAL_BS = int(os.getenv("ELECTRA_EVAL_BS", "32"))
GRAD_ACCUM = int(os.getenv("ELECTRA_GRAD_ACCUM", "2"))
NUM_WORKERS = 0 if os.name == "nt" else 4
SEED = int(os.getenv("ELECTRA_SEED", "42"))

#load data
from data_pipeline.dataset import load_dataset

df = load_dataset()

if "label" not in df.columns:
    raise KeyError("Dataset must contain 'label' column.")

# Normalize labels
label_values = sorted(df["label"].unique().tolist())
label2id = {label: idx for idx, label in enumerate(label_values)}
id2label = {idx: str(label) for label, idx in label2id.items()}
df["label"] = df["label"].map(label2id).astype("int64")

# Stratified split
train_df, temp_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df["label"],
    random_state=42
)

val_df, test_df = train_test_split(
    temp_df,
    test_size=0.5,
    stratify=temp_df["label"],
    random_state=42
)

print("Train:", train_df.shape)
print("Val:", val_df.shape)
print("Test:", test_df.shape)

# tokenizer
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(
        batch["body"],
        truncation=True,
        max_length=128
    )

train_dataset = Dataset.from_pandas(train_df, preserve_index=False)
val_dataset = Dataset.from_pandas(val_df, preserve_index=False)

train_dataset = train_dataset.map(tokenize, batched=True)
val_dataset = val_dataset.map(tokenize, batched=True)

train_dataset = train_dataset.remove_columns(["body"])
val_dataset = val_dataset.remove_columns(["body"])

train_dataset = train_dataset.rename_column("label", "labels")
val_dataset = val_dataset.rename_column("label", "labels")

train_dataset.set_format("torch")
val_dataset.set_format("torch")

# class weights
labels = train_df["label"].values
classes = np.unique(labels)

weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=labels
)

class_weights = torch.tensor(weights, dtype=torch.float).to(device)

# model
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label2id),
    id2label=id2label,
    label2id={str(k): int(v) for k, v in label2id.items()}
).to(device)
if device.type == "cuda":
    model.gradient_checkpointing_enable()

# custom trainer
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")
        loss_fct = nn.CrossEntropyLoss(weight=class_weights)
        loss = loss_fct(logits, labels)
        return (loss, outputs) if return_outputs else loss

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "macro_f1": f1_score(labels, preds, average="macro")
    }

#training args
training_args = TrainingArguments(
    output_dir=str(OUTPUT_DIR),
    eval_strategy="epoch",
    save_strategy="epoch",
    logging_strategy="steps",
    logging_steps=1000,
    learning_rate=3e-5,
    per_device_train_batch_size=TRAIN_BS,
    per_device_eval_batch_size=EVAL_BS,
    auto_find_batch_size=(device.type == "cuda"),
    gradient_accumulation_steps=GRAD_ACCUM,
    dataloader_num_workers=NUM_WORKERS,
    dataloader_pin_memory=(device.type == "cuda"),
    group_by_length=True,
    num_train_epochs=2,               # small model converges fast
    weight_decay=0.01,
    warmup_ratio=0.1,
    load_best_model_at_end=True,
    metric_for_best_model="macro_f1",
    seed=SEED,
    tf32=(device.type == "cuda"),
    report_to="none",
    fp16=(device.type == "cuda")
)

data_collator = DataCollatorWithPadding(
    tokenizer=tokenizer,
    pad_to_multiple_of=8 if torch.cuda.is_available() else None
)

trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    data_collator=data_collator,
    compute_metrics=compute_metrics
)

# train
try:
    trainer.train()
except RuntimeError as exc:
    if "out of memory" in str(exc).lower():
        if device.type == "cuda":
            gc.collect()
            torch.cuda.empty_cache()
            torch.cuda.ipc_collect()
        raise RuntimeError(
            "CUDA OOM encountered. Retry with smaller effective batch, e.g. "
            "`$env:ELECTRA_TRAIN_BS='8'; $env:ELECTRA_GRAD_ACCUM='4'; python training/train_electra_small.py`."
        ) from exc
    raise

# Save final model
trainer.save_model(str(OUTPUT_DIR))
tokenizer.save_pretrained(str(OUTPUT_DIR))

print("Training complete.")
