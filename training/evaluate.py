"""
Held-out evaluation → REPORT/metrics.json, plots, errors.md, RESULTS.md.

Test A: MACD hindi_test
Test C: Davidson 10% holdout

Run after training:
  python training/evaluate.py
"""
from __future__ import annotations

import json
import os
import sys
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import AutoModelForSequenceClassification, AutoTokenizer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (  # noqa: E402
    ID2LABEL,
    INDICES,
    MAX_LENGTH,
    PT,
    ROOT,
    davidson_holdout,
    ensure_raw,
    load_davidson,
    load_macd,
    train_texts,
)

REPORT = os.path.join(ROOT, "REPORT")
THRESHOLDS = (0.5, 0.65, 0.8)


def assert_no_leakage(test_df: pd.DataFrame, name: str, train_set: set[str]) -> dict:
    overlap = test_df[test_df["text"].isin(train_set)]
    n_leak = len(overlap)
    if n_leak:
        raise AssertionError(f"LEAKAGE: {n_leak}/{len(test_df)} rows of {name} in train")
    return {"n": len(test_df), "leakage_rows": 0}


def predict(model, tokenizer, texts: list[str], device) -> tuple[np.ndarray, np.ndarray]:
    preds, probs = [], []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(texts), 64):
            batch = texts[i : i + 64]
            enc = tokenizer(
                batch, padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt"
            ).to(device)
            logits = model(**enc).logits
            p = torch.softmax(logits, dim=-1).cpu().numpy()
            probs.append(p)
            preds.append(p.argmax(axis=-1))
    return np.concatenate(preds), np.concatenate(probs)


def metrics_at_threshold(probs: np.ndarray, labels: np.ndarray, thr: float) -> dict:
    p_abusive = probs[:, 0]
    preds = np.where(p_abusive >= thr, 0, 1)
    return {
        "threshold": thr,
        "accuracy": float(accuracy_score(labels, preds)),
        "f1_macro": float(f1_score(labels, preds, average="macro")),
        "precision_macro": float(precision_score(labels, preds, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(labels, preds, average="macro", zero_division=0)),
    }


def sample_errors(texts, labels, preds, probs, k=8):
    fp, fn = [], []
    for t, y, p, pr in zip(texts, labels, preds, probs):
        row = {"text": t[:200], "true": int(y), "pred": int(p), "p_abusive": float(pr[0])}
        if y == 1 and p == 0:
            fp.append(row)
        elif y == 0 and p == 1:
            fn.append(row)
    return fp[:k], fn[:k]


def plot_confusion(cm_a, cm_c, path):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, cm, title in zip(axes, [cm_a, cm_c], ["Test A (MACD Hindi)", "Test C (Davidson)"]):
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels([ID2LABEL[0], ID2LABEL[1]])
        ax.set_yticklabels([ID2LABEL[0], ID2LABEL[1]])
        ax.set_xlabel("predicted")
        ax.set_ylabel("true")
        ax.set_title(title)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center")
        fig.colorbar(im, ax=ax, fraction=0.046)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def plot_curves(log_history, report_dir):
    train_steps = [e for e in log_history if "loss" in e and "eval_loss" not in e]
    eval_epochs = [e for e in log_history if "eval_loss" in e]

    fig, ax = plt.subplots(figsize=(10, 5))
    if train_steps:
        ax.plot([e["step"] for e in train_steps], [e["loss"] for e in train_steps], label="train loss")
    if eval_epochs:
        ax.plot(
            [e["step"] for e in eval_epochs],
            [e["eval_loss"] for e in eval_epochs],
            label="val loss",
            linestyle="--",
            marker="o",
        )
    ax.set_xlabel("step")
    ax.set_ylabel("loss")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(report_dir, "loss_curves.png"), dpi=150)
    plt.close()

    fig2, ax2 = plt.subplots(figsize=(10, 5))
    f1_epochs = [e["epoch"] for e in eval_epochs if e.get("eval_f1_macro") is not None]
    f1_vals = [e["eval_f1_macro"] for e in eval_epochs if e.get("eval_f1_macro") is not None]
    if f1_vals:
        ax2.plot(f1_epochs, f1_vals, marker="o", label="val macro F1")
    ax2.set_xlabel("epoch")
    ax2.set_ylabel("macro F1")
    ax2.legend()
    ax2.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(report_dir, "f1_curves.png"), dpi=150)
    plt.close()


def write_results_md(metrics: dict, int8_mb: float | None):
    a = metrics["tests"]["test_a_macd_hindi"]
    c = metrics["tests"]["test_c_davidson"]
    lines = [
        "# Results",
        "",
        f"_Generated from FINAL pipeline · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}_",
        "",
        "**Labels:** 0 = abusive, 1 = non-abusive",
        "",
        "## Held-out tests (PyTorch FP32, argmax)",
        "",
        "| Set | N | Acc | Macro F1 |",
        "|---|---:|---:|---:|",
        f"| A — MACD hindi_test | {a['n']} | **{a['accuracy']*100:.2f}%** | {a['f1_macro']*100:.2f}% |",
        f"| C — Davidson holdout | {c['n']} | **{c['accuracy']*100:.2f}%** | {c['f1_macro']*100:.2f}% |",
        "",
        "## Threshold sweep (MACD val, P(abusive))",
        "",
        "| Threshold | Acc | Macro F1 |",
        "|---|---:|---:|",
    ]
    for row in metrics["threshold_val"]:
        lines.append(
            f"| {row['threshold']:.2f} | {row['accuracy']*100:.2f}% | {row['f1_macro']*100:.2f}% |"
        )
    lines += [
        "",
        "## Deploy",
        "",
        "| Artifact | Value |",
        "|---|---|",
        f"| PyTorch checkpoint | `checkpoints/v1/` |",
    ]
    if int8_mb:
        lines.append(f"| INT8 ONNX (shipped) | **{int8_mb:.1f} MB** |")
    lines += [
        "",
        "## Extension (systems)",
        "",
        "- Viewport-only scan (IntersectionObserver); batch classify in service worker",
        "- Store abusive hits only: SHA-256 + 280-char preview, max 100 rows, 30-day TTL",
        "- Append-only hash chain; Verify + Export JSON in popup",
        "- Auto-export JSON on HIGH severity via `chrome.downloads`",
        "- Threat model: tamper-**evident**, not hacker-proof (DevTools can wipe storage)",
        "",
        "## Curves",
        "",
        "![loss](loss_curves.png)",
        "",
        "![f1](f1_curves.png)",
        "",
        "![cm](confusion_matrices.png)",
        "",
        "## Sample errors",
        "",
        "See [errors.md](errors.md).",
    ]
    with open(os.path.join(REPORT, "RESULTS.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main(log_history=None):
    ensure_raw()
    assert os.path.isdir(PT), f"missing {PT} — run training/train.py first"

    train_set = train_texts()
    test_a = load_macd("hindi_test")
    _, test_c, _ = davidson_holdout(load_davidson(), INDICES)
    val_df = load_macd("hindi_val")

    leakage = {
        "test_a": assert_no_leakage(test_a, "Test A", train_set),
        "test_c": assert_no_leakage(test_c, "Test C", train_set),
    }
    print("leakage OK:", leakage)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(PT)
    model = AutoModelForSequenceClassification.from_pretrained(PT).to(device)

    results = {}
    errors = {}
    for name, df in [("test_a_macd_hindi", test_a), ("test_c_davidson", test_c)]:
        texts = df["text"].tolist()
        labels = df["label"].values.astype(int)
        preds, probs = predict(model, tokenizer, texts, device)
        cm = confusion_matrix(labels, preds, labels=[0, 1])
        results[name] = {
            "n": len(df),
            "accuracy": float(accuracy_score(labels, preds)),
            "f1_macro": float(f1_score(labels, preds, average="macro")),
            "precision_macro": float(precision_score(labels, preds, average="macro", zero_division=0)),
            "recall_macro": float(recall_score(labels, preds, average="macro", zero_division=0)),
            "confusion_matrix": cm.tolist(),
        }
        fp, fn = sample_errors(texts, labels, preds, probs)
        errors[name] = {"false_positives": fp, "false_negatives": fn}
        print(f"{name}: acc={results[name]['accuracy']:.4f} f1={results[name]['f1_macro']:.4f}")

    val_texts = val_df["text"].tolist()
    val_labels = val_df["label"].values.astype(int)
    _, val_probs = predict(model, tokenizer, val_texts, device)
    threshold_val = [metrics_at_threshold(val_probs, val_labels, t) for t in THRESHOLDS]

    os.makedirs(REPORT, exist_ok=True)
    if log_history:
        plot_curves(log_history, REPORT)
    plot_confusion(
        np.array(results["test_a_macd_hindi"]["confusion_matrix"]),
        np.array(results["test_c_davidson"]["confusion_matrix"]),
        os.path.join(REPORT, "confusion_matrices.png"),
    )

    int8_path = os.path.join(ROOT, "assets", "models", "custom-macd-model", "onnx", "model_quantized.onnx")
    int8_mb = os.path.getsize(int8_path) / 1e6 if os.path.exists(int8_path) else None

    metrics = {"leakage": leakage, "tests": results, "threshold_val": threshold_val, "int8_size_mb": int8_mb}
    with open(os.path.join(REPORT, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    err_lines = ["# Sample errors\n"]
    for name, e in errors.items():
        err_lines.append(f"## {name}\n\n### False positives\n")
        for r in e["false_positives"]:
            err_lines.append(f"- `{r['text'][:120]}…` (p_ab={r['p_abusive']:.2f})\n")
        err_lines.append("\n### False negatives\n")
        for r in e["false_negatives"]:
            err_lines.append(f"- `{r['text'][:120]}…` (p_ab={r['p_abusive']:.2f})\n")
        err_lines.append("\n")
    with open(os.path.join(REPORT, "errors.md"), "w") as f:
        f.write("".join(err_lines))

    write_results_md(metrics, int8_mb)
    print(f"wrote {REPORT}/metrics.json, RESULTS.md, errors.md")


if __name__ == "__main__":
    main()
