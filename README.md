# SurakshaNet — FINAL (interview pack)

On-device abuse detection for Hindi (Devanagari) + English. Systems story: viewport scan, bounded evidence, hash chain, export-on-HIGH.

**Read order:** `README.md` → `REPORT/RESULTS.md` → `training/train.py` → `quantization-and-export/export_int8.py` → `src/`

---

## Layout

```
FINAL/
├── dataset/download.py       MACD + Davidson
├── training/
│   ├── train.py              HF Trainer (Ch.3 API)
│   ├── evaluate.py           held-out A + C → REPORT
│   └── run_modal.py          GPU train + eval on Modal
├── quantization-and-export/export_int8.py
├── REPORT/                   metrics.json, RESULTS.md, curves
├── src/                      Chrome MV3 extension
└── assets/models/            INT8 ONNX (after export)
```

## Model

Binary: **0 = abusive**, **1 = non-abusive**.  
Trained on MACD Hindi + Davidson English (90% train / 10% held-out test C).

Numbers live only in `REPORT/RESULTS.md` from the latest `run_modal.py` + `export_int8.py` run.

## Train + evaluate (GPU)

```bash
cd FINAL
pip install -r training/requirements.txt
python dataset/download.py
modal run training/run_modal.py
python quantization-and-export/export_int8.py
python training/evaluate.py   # optional: refresh REPORT after INT8 size known
```

Local CPU (slow):

```bash
python training/train.py
python training/evaluate.py
python quantization-and-export/export_int8.py
```

HF Trainer pattern: https://huggingface.co/learn/llm-course/chapter3/3

## Extension

```bash
npm install && npm run build
# Chrome → Load unpacked → dist/
```

Features: viewport-only scan, abusive-only storage (100 cap, 30d TTL), hash chain, verify/export popup, auto JSON download on HIGH severity.
