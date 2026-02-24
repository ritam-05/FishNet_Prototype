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

# ---------------- CONFIG ----------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = "google/electra-small-discriminator"
MODELS_DIR = PROJECT_ROOT / "models"
MODEL_DIR = MODELS_DIR / "electra_small_android"
FINAL_EXPORT_DIR = MODEL_DIR

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

TRAIN_BS = int(os.getenv("ELECTRA_TRAIN_BS", "16"))
EVAL_BS = int(os.getenv("ELECTRA_EVAL_BS", "32"))
GRAD_ACCUM = int(os.getenv("ELECTRA_GRAD_ACCUM", "2"))
NUM_WORKERS = 0 if os.name == "nt" else 4
SEED = int(os.getenv("ELECTRA_SEED", "42"))

MAX_LENGTH = 64  #  REDUCED FOR MOBILE

# ---------------- LOAD DATA ----------------
from data_pipeline.dataset import load_dataset
df = load_dataset()

if "label" not in df.columns:
    raise KeyError("Dataset must contain 'label' column.")

label_values = sorted(df["label"].unique().tolist())
label2id = {label: idx for idx, label in enumerate(label_values)}
id2label = {idx: str(label) for label, idx in label2id.items()}
df["label"] = df["label"].map(label2id).astype("int64")

train_df, temp_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df["label"],
    random_state=SEED
)

val_df, test_df = train_test_split(
    temp_df,
    test_size=0.5,
    stratify=temp_df["label"],
    random_state=SEED
)

print("Train:", train_df.shape)
print("Val:", val_df.shape)
print("Test:", test_df.shape)

# ---------------- TOKENIZER ----------------
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(
        batch["body"],
        truncation=True,
        max_length=MAX_LENGTH
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

# ---------------- CLASS WEIGHTS ----------------
labels = train_df["label"].values
classes = np.unique(labels)

weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=labels
)

class_weights = torch.tensor(weights, dtype=torch.float).to(device)

# ---------------- MODEL ----------------
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label2id),
    id2label=id2label,
    label2id=label2id  # clean mapping
).to(device)

#  Removed gradient_checkpointing (not needed for small model)

# ---------------- CUSTOM TRAINER ----------------
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

# ---------------- TRAINING ARGS ----------------
training_args = TrainingArguments(
    output_dir=str(MODEL_DIR),
    evaluation_strategy="epoch",
    save_strategy="epoch",
    learning_rate=3e-5,
    per_device_train_batch_size=TRAIN_BS,
    per_device_eval_batch_size=EVAL_BS,
    gradient_accumulation_steps=GRAD_ACCUM,
    dataloader_num_workers=NUM_WORKERS,
    group_by_length=True,
    num_train_epochs=2,
    weight_decay=0.01,
    warmup_ratio=0.1,
    load_best_model_at_end=True,
    metric_for_best_model="macro_f1",
    seed=SEED,
    report_to="none",
    fp16=torch.cuda.is_available()  # keep if GPU
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

# ---------------- TRAIN ----------------
trainer.train()

FINAL_EXPORT_DIR.mkdir(parents=True, exist_ok=True)

trainer.save_model(str(FINAL_EXPORT_DIR))
tokenizer.save_pretrained(str(FINAL_EXPORT_DIR))

print("Training complete.")
