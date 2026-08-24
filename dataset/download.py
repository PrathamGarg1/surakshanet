"""Download MACD Hindi + Davidson English into dataset/raw/."""
from __future__ import annotations

import os
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(ROOT, "raw")
UA = {"User-Agent": "Mozilla/5.0"}

MACD = "https://raw.githubusercontent.com/ShareChatAI/MACD/main/dataset/"
DAVIDSON = (
    "https://raw.githubusercontent.com/t-davidson/"
    "hate-speech-and-offensive-language/master/data/labeled_data.csv"
)


def fetch(url: str, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        print(f"exists {path}")
        return
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req) as r, open(path, "wb") as f:
        f.write(r.read())
    print(f"wrote {path}")


def main():
    for split in ("hindi_train", "hindi_val", "hindi_test"):
        fetch(f"{MACD}{split}.csv", os.path.join(RAW, f"{split}.csv"))
    fetch(DAVIDSON, os.path.join(RAW, "davidson.csv"))


if __name__ == "__main__":
    main()
