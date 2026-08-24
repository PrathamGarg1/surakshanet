"""Shared constants and dataset loaders for FINAL training pipeline."""
from __future__ import annotations

import json
import os
import urllib.request

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "dataset", "raw")
INDICES = os.path.join(ROOT, "checkpoints", "davidson_test_indices.json")
PT = os.path.join(ROOT, "checkpoints", "v1")

MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
ID2LABEL = {0: "abusive", 1: "non-abusive"}
LABEL2ID = {"abusive": 0, "non-abusive": 1}
DAVIDSON_MAP = {0: 0, 1: 0, 2: 1}
SEED = 42
MAX_LENGTH = 128

HP = {
    "epochs": 7,
    "lr": 3e-5,
    "batch_size": 32,
    "eval_batch_size": 64,
    "weight_decay": 0.01,
    "warmup_ratio": 0.1,
    "lr_scheduler_type": "cosine",
    "label_smoothing": 0.1,
    "metric_for_best_model": "f1_macro",
}

MACD_URL = "https://raw.githubusercontent.com/ShareChatAI/MACD/main/dataset/"
DAVIDSON_URL = (
    "https://raw.githubusercontent.com/t-davidson/"
    "hate-speech-and-offensive-language/master/data/labeled_data.csv"
)


def _fetch(url: str, path: str) -> None:
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r, open(path, "wb") as f:
        f.write(r.read())


def ensure_raw() -> None:
    for split in ("hindi_train", "hindi_val", "hindi_test"):
        _fetch(f"{MACD_URL}{split}.csv", os.path.join(RAW, f"{split}.csv"))
    _fetch(DAVIDSON_URL, os.path.join(RAW, "davidson.csv"))


def load_macd(split: str) -> pd.DataFrame:
    assert split in ("hindi_train", "hindi_val", "hindi_test")
    df = pd.read_csv(os.path.join(RAW, f"{split}.csv"))
    for old, new in [("comment_text", "text"), ("tweet", "text"), ("class", "label")]:
        if old in df.columns:
            df = df.rename(columns={old: new})
    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str)
    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype(int)
    return df[df["label"].isin([0, 1])].reset_index(drop=True)


def load_davidson() -> pd.DataFrame:
    df = pd.read_csv(os.path.join(RAW, "davidson.csv"))
    text_col = "tweet" if "tweet" in df.columns else "text"
    label_col = "class" if "class" in df.columns else "label"
    df = df.rename(columns={text_col: "text", label_col: "label"})
    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str)
    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype(int).map(DAVIDSON_MAP)
    return df.dropna(subset=["label"]).astype({"label": int}).reset_index(drop=True)


def davidson_holdout(df: pd.DataFrame, indices_file: str | None = None):
    """90/10 split; persist test indices for evaluate."""
    path = indices_file or INDICES
    if path and os.path.exists(path):
        with open(path) as f:
            test_idx = sorted(int(i) for i in json.load(f))
    else:
        idx = np.arange(len(df))
        _, test_idx = train_test_split(idx, test_size=0.1, random_state=SEED)
        test_idx = sorted(int(i) for i in test_idx)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(test_idx, f)
    mask = np.zeros(len(df), dtype=bool)
    mask[test_idx] = True
    return df.iloc[~mask].reset_index(drop=True), df.iloc[mask].reset_index(drop=True), test_idx


def train_texts() -> set[str]:
    """All texts seen during training (incl. val) — for leakage check."""
    ensure_raw()
    macd_train = load_macd("hindi_train")
    macd_val = load_macd("hindi_val")
    davidson = load_davidson()
    d_train, _, _ = davidson_holdout(davidson, INDICES)
    all_texts = pd.concat([macd_train["text"], macd_val["text"], d_train["text"]], ignore_index=True)
    return set(all_texts.tolist())
