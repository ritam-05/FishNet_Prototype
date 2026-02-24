#stratified split
import sys
from pathlib import Path
import os
import gc

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = os.getenv("MODEL_NAME", "roberta-base")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data_pipeline.dataset import load_dataset
from sklearn.model_selection import train_test_split

# Load cleaned dataset
df = load_dataset()

if "label" not in df.columns:
    raise KeyError("Dataset must contain a 'label' column.")

# Normalize labels to contiguous ids [0..num_labels-1] for CrossEntropyLoss.
label_values = sorted(df["label"].unique().tolist())
label2id = {label: idx for idx, label in enumerate(label_values)}
id2label = {idx: str(label) for label, idx in label2id.items()}
df["label"] = df["label"].map(label2id).astype("int64")
num_labels = len(label2id)

# 80% train, 20% temp
train_df, temp_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df["label"],
    random_state=42
)

# 10% validation, 10% test
val_df, test_df = train_test_split(
    temp_df,
    test_size=0.5,
    stratify=temp_df["label"],
    random_state=42
)

print("Train:", train_df.shape)
print("Val:", val_df.shape)
print("Test:", test_df.shape)
print("\nTrain distribution:\n", train_df["label"].value_counts())

#load tokenizer
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

#convert to hugging face dataset
from datasets import Dataset

train_dataset = Dataset.from_pandas(train_df, preserve_index=False)
val_dataset = Dataset.from_pandas(val_df, preserve_index=False)
test_dataset = Dataset.from_pandas(test_df, preserve_index=False)

def tokenize(batch):
    return tokenizer(
        batch["body"],
        truncation=True,
        max_length=128
    )

train_dataset = train_dataset.map(tokenize, batched=True)
val_dataset = val_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.map(tokenize, batched=True)

train_dataset = train_dataset.remove_columns(["body"])
val_dataset = val_dataset.remove_columns(["body"])
test_dataset = test_dataset.remove_columns(["body"])

train_dataset = train_dataset.rename_column("label", "labels")
val_dataset = val_dataset.rename_column("label", "labels")
test_dataset = test_dataset.rename_column("label", "labels")

train_dataset.set_format("torch")
val_dataset.set_format("torch")
test_dataset.set_format("torch")

#compute class weights
import torch
import numpy as np
from sklearn.utils.class_weight import compute_class_weight

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
if device.type == "cuda":
    # Faster tensor-core matmul on supported NVIDIA GPUs.
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

def clear_cuda_cache():
    if device.type == "cuda":
        gc.collect()
        torch.cuda.empty_cache()
        torch.cuda.ipc_collect()

labels = train_df["label"].values
classes = np.unique(labels)

weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=labels
)

class_weights = torch.tensor(weights, dtype=torch.float).to(device)

print("Class Weights:", class_weights)
clear_cuda_cache()

#load model
from transformers import AutoModelForSequenceClassification

# Keep trainable model weights in FP32; Trainer AMP handles mixed precision.
model_dtype = torch.float32

try:
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=num_labels,
        id2label=id2label,
        label2id={k: int(v) for k, v in label2id.items()},
        low_cpu_mem_usage=True,
        torch_dtype=model_dtype,
    )
    if any(param.is_meta for param in model.parameters()):
        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_NAME,
            num_labels=num_labels,
            id2label=id2label,
            label2id={k: int(v) for k, v in label2id.items()},
            torch_dtype=model_dtype,
        )
    model = model.to(device)
except ImportError as exc:
    if "accelerate" in str(exc).lower():
        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_NAME,
            num_labels=num_labels,
            id2label=id2label,
            label2id={k: int(v) for k, v in label2id.items()},
            torch_dtype=model_dtype,
        ).to(device)
    else:
        raise
except OSError as exc:
    if "1455" in str(exc):
        raise RuntimeError(
            "Model load failed due to low Windows virtual memory (paging file). "
            "Increase paging file size or run with a smaller model, e.g. "
            "`$env:MODEL_NAME='distilroberta-base'; python train_roBERTa.py`."
        ) from exc
    raise

#custom trainer with weighted loss
from transformers import Trainer, TrainingArguments, DataCollatorWithPadding
import torch.nn as nn

class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")
        loss_fct = nn.CrossEntropyLoss(weight=class_weights)
        loss = loss_fct(logits, labels)
        return (loss, outputs) if return_outputs else loss

#metrics
# from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# def compute_metrics(eval_pred):
#     logits, labels = eval_pred
#     preds = np.argmax(logits, axis=1)

#     precision, recall, f1, _ = precision_recall_fscore_support(
#         labels, preds, average="macro"
#     )

#     acc = accuracy_score(labels, preds)

#     return {
#         "accuracy": acc,
#         "macro_f1": f1,
#         "precision": precision,
#         "recall": recall
#     }

#training args
num_workers = 0 if os.name == "nt" else 4

training_args = TrainingArguments(
    output_dir=str(PROJECT_ROOT / "models" / "roberta_model"),
    eval_strategy="epoch",
    save_strategy="epoch",
    report_to="none",
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    dataloader_num_workers=num_workers,
    dataloader_pin_memory=(device.type == "cuda"),
    num_train_epochs=3,
    weight_decay=0.01,
    warmup_ratio=0.1,
    load_best_model_at_end=True,
    metric_for_best_model="macro_f1",
    tf32=(device.type == "cuda"),
    fp16=(device.type == "cuda")
)

#training
data_collator = DataCollatorWithPadding(
    tokenizer=tokenizer,
    pad_to_multiple_of=8 if device.type == "cuda" else None
)

trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    data_collator=data_collator,
    # compute_metrics=compute_metrics
)

clear_cuda_cache()
trainer.train()
clear_cuda_cache()
trainer.save_model(str(PROJECT_ROOT / "models" / "roberta_model"))
tokenizer.save_pretrained(str(PROJECT_ROOT / "models" / "roberta_model"))
