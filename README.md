# SurakshaNet

On-device **WhatsApp Web** abuse detection (Hindi Devanagari). Viewport scan, bounded evidence, hash chain, export-on-HIGH.

**Read order:** `README.md` → `REPORT/RESULTS.md` → `training/train.py` → `src/`

---

## Layout

```
├── dataset/download.py       MACD + Davidson
├── training/                 HF Trainer + Modal pipeline
├── quantization-and-export/export_int8.py
├── REPORT/                   metrics + curves
├── src/                      Chrome MV3 extension
└── assets/models/            INT8 ONNX
```

## Model

Binary: **0 = abusive**, **1 = non-abusive**.  
Trained on MACD Hindi + Davidson English.

Numbers: `REPORT/RESULTS.md`

## Train (GPU)

```bash
pip install -r training/requirements.txt
python dataset/download.py
modal run training/run_modal.py
```

## Extension (WhatsApp only)

```bash
npm install && npm run build
# Chrome → Load unpacked → dist/
```

Reload after rebuild. On WhatsApp Web you should see a purple **“SurakshaNet · scanning WhatsApp”** badge bottom-right.
