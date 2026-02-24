import os
import torch
import numpy as np
from pathlib import Path
from transformers import AutoTokenizer
from optimum.onnxruntime import ORTModelForSequenceClassification
from onnxruntime.quantization import quantize_dynamic, QuantType
import onnxruntime as ort

# ---------------- CONFIG ----------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_DIR = PROJECT_ROOT / "models" / "electra_small_android"
ONNX_DIR = PROJECT_ROOT / "models" / "electra_small_android_onnx"
QUANT_MODEL_PATH = ONNX_DIR / "model_int8.onnx"

MAX_LENGTH = 64

ONNX_DIR.mkdir(parents=True, exist_ok=True)

print("\n===== EXPORTING ELECTRA TO ONNX =====")

# ---------------- EXPORT TO ONNX ----------------
print("Loading PyTorch model...")
ort_model = ORTModelForSequenceClassification.from_pretrained(
    MODEL_DIR,
    export=True
)

print("Saving ONNX model...")
ort_model.save_pretrained(ONNX_DIR)

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
tokenizer.save_pretrained(ONNX_DIR)

onnx_model_path = ONNX_DIR / "model.onnx"

print("ONNX export complete.")
print(f"ONNX path: {onnx_model_path}")

# ---------------- QUANTIZE ----------------
print("\nQuantizing to INT8...")
quantize_dynamic(
    model_input=str(onnx_model_path),
    model_output=str(QUANT_MODEL_PATH),
    weight_type=QuantType.QInt8
)

print("Quantization complete.")
print(f"Quantized model path: {QUANT_MODEL_PATH}")

# ---------------- SIZE COMPARISON ----------------
original_size = os.path.getsize(onnx_model_path) / (1024 * 1024)
quant_size = os.path.getsize(QUANT_MODEL_PATH) / (1024 * 1024)

print("\n===== MODEL SIZE =====")
print(f"ONNX FP32 size: {original_size:.2f} MB")
print(f"ONNX INT8 size: {quant_size:.2f} MB")

# ---------------- TEST INFERENCE ----------------
print("\n===== TESTING ONNX INFERENCE =====")

session = ort.InferenceSession(str(QUANT_MODEL_PATH), providers=["CPUExecutionProvider"])

dummy_text = "This is a test notification message."
inputs = tokenizer(
    dummy_text,
    truncation=True,
    padding="max_length",
    max_length=MAX_LENGTH,
    return_tensors="np"
)

required_inputs = [inp.name for inp in session.get_inputs()]
input_feed = {}

for name in required_inputs:
    if name in inputs:
        arr = inputs[name]
        if np.issubdtype(arr.dtype, np.integer):
            arr = arr.astype(np.int64, copy=False)
        input_feed[name] = arr
    elif name == "token_type_ids":
        # Some exported ELECTRA graphs require token_type_ids explicitly.
        input_feed[name] = np.zeros_like(inputs["input_ids"], dtype=np.int64)
    else:
        raise KeyError(
            f"ONNX model requires unexpected input '{name}' that is not provided by tokenizer."
        )

outputs = session.run(None, input_feed)
logits = outputs[0]
probs = torch.nn.functional.softmax(torch.tensor(logits), dim=1).numpy()

print("Sample prediction probabilities:", probs)
print("\nONNX pipeline verified successfully.")
