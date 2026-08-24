# Datasets

| Source | Use |
|---|---|
| **MACD** Hindi train/val/test | Abuse labels (ShareChat, Devanagari) |
| **Davidson 2017** | English hate/offensive → binary abusive |

```bash
python dataset/download.py   # → dataset/raw/
```

- MACD: https://github.com/ShareChatAI/MACD
- Davidson: https://github.com/t-davidson/hate-speech-and-offensive-language

Train = MACD `hindi_train` + Davidson 90%. Val = MACD `hindi_val`. Test A = `hindi_test`. Test C = Davidson 10% holdout.
