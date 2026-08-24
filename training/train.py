"""
Fine-tune MiniLM with Hugging Face Trainer (Ch.3 API).

Data: MACD Hindi train/val + Davidson English 90%.
https://huggingface.co/learn/llm-course/chapter3/3

Run:
  python dataset/download.py
  python training/train.py
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score
from sklearn.utils.class_weight import compute_class_weight
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    set_seed,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (  # noqa: E402
    HP,
    ID2LABEL,
    INDICES,
    LABEL2ID,
    MAX_LENGTH,
    MODEL_NAME,
    PT,
    ROOT,
    SEED,
    davidson_holdout,
    ensure_raw,
    load_davidson,
    load_macd,
)


def build_frames():
    macd_train, macd_val = load_macd("hindi_train"), load_macd("hindi_val")
    d_train, _, _ = davidson_holdout(load_davidson(), INDICES)
    train_df = pd.concat([macd_train, d_train], ignore_index=True)
    train_df = train_df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    print(f"train={len(train_df)} val={len(macd_val)}")
    return train_df, macd_val


def main():
    set_seed(SEED)
    ensure_raw()
    train_df, val_df = build_frames()

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2, id2label=ID2LABEL, label2id=LABEL2ID
    )

    def tokenize(batch):
        return tokenizer(
            batch["text"], padding="max_length", truncation=True, max_length=MAX_LENGTH
        )

    def to_ds(df):
        ds = Dataset.from_pandas(df[["text", "label"]], preserve_index=False)
        ds = ds.map(tokenize, batched=True)
        ds = ds.remove_columns(["text"])
        ds.set_format("torch")
        return ds

    train_ds, val_ds = to_ds(train_df), to_ds(val_df)
    weights = torch.tensor(
        compute_class_weight("balanced", classes=np.array([0, 1]), y=train_df["label"].values),
        dtype=torch.float32,
    )

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            loss = nn.CrossEntropyLoss(
                weight=weights.to(outputs.logits.device), label_smoothing=HP["label_smoothing"]
            )(outputs.logits.view(-1, 2), labels.view(-1))
            return (loss, outputs) if return_outputs else loss

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, preds),
            "f1_macro": f1_score(labels, preds, average="macro"),
        }

    training_args = TrainingArguments(
        output_dir=os.path.join(ROOT, "checkpoints", "_runs"),
        num_train_epochs=HP["epochs"],
        learning_rate=HP["lr"],
        per_device_train_batch_size=HP["batch_size"],
        per_device_eval_batch_size=HP["eval_batch_size"],
        weight_decay=HP["weight_decay"],
        warmup_ratio=HP["warmup_ratio"],
        lr_scheduler_type=HP["lr_scheduler_type"],
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model=HP["metric_for_best_model"],
        greater_is_better=True,
        save_total_limit=1,
        fp16=torch.cuda.is_available(),
        seed=SEED,
        report_to=[],
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    os.makedirs(PT, exist_ok=True)
    trainer.save_model(PT)
    tokenizer.save_pretrained(PT)
    print(f"saved {PT}")


if __name__ == "__main__":
    main()
