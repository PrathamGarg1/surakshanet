"""
Modal GPU: train + evaluate + INT8 export → pull artifacts to FINAL/.

  cd FINAL
  modal run training/run_modal.py
"""
from __future__ import annotations

import json
import os
import shutil

import modal

TRAINING_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TRAINING_DIR)

IMAGE = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install(
        "torch==2.1.2",
        "transformers==4.36.2",
        "datasets==2.16.1",
        "accelerate==0.25.0",
        "scikit-learn==1.3.2",
        "pandas==2.1.4",
        "numpy==1.24.4",
        "matplotlib==3.8.2",
        "optimum[onnxruntime]==1.16.1",
        "onnxruntime==1.16.3",
        "onnx==1.16.0",
        "protobuf==4.25.2",
        "sentencepiece==0.1.99",
    )
    .add_local_dir(TRAINING_DIR, remote_path="/root/training")
)

VOLUME = modal.Volume.from_name("surakshanet-final", create_if_missing=True)
VOL = "/vol"
app = modal.App("surakshanet-final")


def export_int8(pt_dir: str, out_dir: str) -> float:
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    from transformers import AutoTokenizer

    fp32 = f"{VOL}/checkpoints/onnx_fp32"
    int8 = f"{VOL}/checkpoints/onnx_int8"
    for d in (fp32, int8):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    tok = AutoTokenizer.from_pretrained(pt_dir)
    ort = ORTModelForSequenceClassification.from_pretrained(pt_dir, export=True)
    ort.save_pretrained(fp32)
    tok.save_pretrained(fp32)
    ORTQuantizer.from_pretrained(fp32).quantize(
        save_dir=int8,
        quantization_config=AutoQuantizationConfig.avx2(is_static=False, per_channel=False),
    )
    tok.save_pretrained(int8)

    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(os.path.join(out_dir, "onnx"), exist_ok=True)
    for src, rel in [
        ("model_quantized.onnx", "onnx/model_quantized.onnx"),
        ("config.json", "config.json"),
        ("ort_config.json", "ort_config.json"),
        ("tokenizer.json", "tokenizer.json"),
        ("tokenizer_config.json", "tokenizer_config.json"),
        ("special_tokens_map.json", "special_tokens_map.json"),
    ]:
        sp = os.path.join(int8, src)
        if os.path.exists(sp):
            dp = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dp), exist_ok=True)
            shutil.copy2(sp, dp)
            print(f"exported {rel} ({os.path.getsize(dp) / 1e6:.1f} MB)")

    return os.path.getsize(os.path.join(out_dir, "onnx/model_quantized.onnx")) / 1e6


@app.function(image=IMAGE, gpu="A10G", volumes={VOL: VOLUME}, timeout=60 * 60 * 3)
def run():
    import io
    import sys
    import tarfile

    sys.path.insert(0, "/root/training")
    os.chdir("/root")

    import _common as c  # noqa: E402
    import evaluate as eval_mod  # noqa: E402
    import train as train_mod  # noqa: E402

    c.ROOT = VOL
    c.RAW = f"{VOL}/dataset/raw"
    c.INDICES = f"{VOL}/checkpoints/davidson_test_indices.json"
    c.PT = f"{VOL}/checkpoints/v1"

    train_mod.ROOT = VOL
    train_mod.PT = c.PT
    train_mod.INDICES = c.INDICES
    eval_mod.ROOT = VOL
    eval_mod.PT = c.PT
    eval_mod.INDICES = c.INDICES
    eval_mod.REPORT = f"{VOL}/REPORT"

    if not os.path.isdir(c.PT):
        train_mod.main()
    else:
        print(f"checkpoint exists at {c.PT}, skipping train")

    log_history = []
    runs = f"{VOL}/checkpoints/_runs"
    if os.path.isdir(runs):
        for root, _, files in os.walk(runs):
            if "trainer_state.json" in files:
                with open(os.path.join(root, "trainer_state.json")) as f:
                    log_history = json.load(f).get("log_history", [])
                break

    eval_mod.main(log_history=log_history)

    ext = f"{VOL}/assets/models/custom-macd-model"
    int8_mb = export_int8(c.PT, ext)

    metrics_path = f"{VOL}/REPORT/metrics.json"
    with open(metrics_path) as f:
        metrics = json.load(f)
    metrics["int8_size_mb"] = round(int8_mb, 1)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    eval_mod.write_results_md(metrics, int8_mb)

    VOLUME.commit()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in (
            "checkpoints/v1",
            "checkpoints/davidson_test_indices.json",
            "REPORT",
            "assets/models/custom-macd-model",
        ):
            path = os.path.join(VOL, rel)
            if os.path.exists(path):
                tar.add(path, arcname=rel)
    buf.seek(0)
    return buf.read()


@app.local_entrypoint()
def main():
    print("==> Modal train + evaluate + INT8 export…")
    data = run.remote()
    tar_path = os.path.join(ROOT, "_modal_artifacts.tar.gz")
    with open(tar_path, "wb") as f:
        f.write(data)

    import tarfile

    assets = os.path.join(ROOT, "assets", "models", "custom-macd-model")
    if os.path.islink(assets):
        os.unlink(assets)

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(ROOT)
    os.remove(tar_path)

    print(f"==> artifacts extracted to {ROOT}")
    print("==> done: checkpoints, REPORT, INT8 model in assets/models/")
