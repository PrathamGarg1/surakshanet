"""
PyTorch checkpoint → ONNX FP32 → INT8 dynamic quantize.
Writes assets/models/custom-macd-model/ for the Chrome extension.

Run after training:
  python quantization-and-export/export_int8.py
"""
from __future__ import annotations

import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PT = os.path.join(ROOT, "checkpoints", "v1")
FP32 = os.path.join(ROOT, "checkpoints", "onnx_fp32")
INT8 = os.path.join(ROOT, "checkpoints", "onnx_int8")
EXT = os.path.join(ROOT, "assets", "models", "custom-macd-model")


def main():
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    from transformers import AutoTokenizer

    assert os.path.isdir(PT), f"missing {PT} — run training/train.py first"

    for d in (FP32, INT8):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    print("export ONNX FP32…")
    tok = AutoTokenizer.from_pretrained(PT)
    ort = ORTModelForSequenceClassification.from_pretrained(PT, export=True)
    ort.save_pretrained(FP32)
    tok.save_pretrained(FP32)

    print("quantize INT8 (avx2 dynamic, per-tensor)…")
    ORTQuantizer.from_pretrained(FP32).quantize(
        save_dir=INT8,
        quantization_config=AutoQuantizationConfig.avx2(is_static=False, per_channel=False),
    )
    tok.save_pretrained(INT8)

    # Layout expected by @xenova/transformers (quantized: true)
    files = [
        ("model_quantized.onnx", "onnx/model_quantized.onnx"),
        ("config.json", "config.json"),
        ("ort_config.json", "ort_config.json"),
        ("tokenizer.json", "tokenizer.json"),
        ("tokenizer_config.json", "tokenizer_config.json"),
        ("special_tokens_map.json", "special_tokens_map.json"),
    ]
    if os.path.islink(EXT) or os.path.exists(EXT):
        # replace symlink with real dir if needed
        if os.path.islink(EXT):
            os.unlink(EXT)
        elif os.path.isdir(EXT):
            shutil.rmtree(EXT)
    os.makedirs(os.path.join(EXT, "onnx"), exist_ok=True)
    for src, rel in files:
        src_path = os.path.join(INT8, src)
        if not os.path.exists(src_path):
            print(f"skip missing {src}")
            continue
        dst = os.path.join(EXT, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src_path, dst)
        print(f"→ {dst} ({os.path.getsize(dst) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
