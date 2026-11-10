# SurakshaNet

Privacy-first, on-device detection of abusive messages in English, Hindi and Hinglish, with a chat-thread benchmark for women and child safety.

SurakshaNet runs a quantized multilingual MiniLM inside a Chrome extension (ONNX Runtime Web / Transformers.js, WebAssembly), so message text never leaves the browser. This repository holds the system from the accepted MobiSys '26 poster (v1), its extension (v2: Hinglish-aware model and a gated conversational window), and a new five-class, context-thread dataset and the models trained on it.

- Poster: *SurakshaNet: Privacy-First, Edge-Deployed Multilingual Abusive Language Detection*, MobiSys Companion '26, [doi:10.1145/3812835.3814864](https://doi.org/10.1145/3812835.3814864) (`paper/accepted_poster_MobiSys26.pdf`)
- Extended report (this repository's paper): `paper/SurakshaNet_V2.pdf`, source in `paper/`

## Repository layout

| Folder | What it contains |
|---|---|
| [`paper/`](paper) | LaTeX source of the extended report, TikZ figures, bibliography, PDFs |
| [`poster_v1/`](poster_v1) | The system of the accepted poster: MV3 extension (`src/`), Modal training pipeline (`training/`), v1 reports (`REPORTS/`) |
| [`extension_v2/`](extension_v2) | Extension with the Hinglish-aware model and the gated conversational window (`sw.js`, `narrative_cache.js`) |
| [`hinglish_context/`](hinglish_context) | MACD-to-Hinglish dataset, conversational test slices, gate and cloud-LLM benchmarks, training scripts |
| [`thread_benchmark/`](thread_benchmark) | **New:** 105,000-thread five-class dataset, generation pipeline, thread models, INT8 export, evaluation |

## What is new

1. **Five-class thread dataset (105,000 threads).** Classes: benign, friendly sarcasm, hostile abuse, sexual harassment, predatory grooming. Three scripts (English, Hindi in Devanagari, Hinglish), thread lengths 3 / 5 / 7 / 10, 17 columns per record. The label belongs to the *last message given the earlier ones*; about half of the sarcasm and hostile threads end in an identical line, so only the context separates them. See [`thread_benchmark/dataset/DATASET_CARD.md`](thread_benchmark/dataset/DATASET_CARD.md).
2. **Generation method.** A seeded scenario sampler (31 subtypes, 40 topics, named speakers, audience, target gender and age) feeds Qwen3-32B on Amazon Bedrock. Rule-based validators check turn count, refusals, script, profanity and explicit words outside the hostile class, and sexualised words in grooming threads; threads are de-duplicated, and pair lines are split by line. Code: [`thread_benchmark/scripts/`](thread_benchmark/scripts).
3. **Thread-aware models.** A fine-tuned MiniLM that reads the last message plus earlier turns, a last-message-only control, and a frozen MiniLM + GRU variant (198,021 trained weights, JavaScript runtime with parity test). Dynamic INT8 export of both routes.
4. **Gated conversational window for the extension.** The window of up to 8 turns / 96 tokens is scored only when the new turn is short and history exists; the final score is the maximum of the message and window scores.

## Headline results

Five-class models, held-out synthetic test set (10,563 threads):

| Model | Size | Accuracy | Macro-F1 |
|---|---|---|---|
| Thread model, INT8 | 118.2 MB | 97.88% | 0.979 |
| Thread model, FP32 | 470.8 MB | 97.96% | 0.980 |
| Frozen MiniLM + GRU, INT8 | 118 MB + 0.8 MB | 94.91% | 0.950 |
| Last message only | 470.8 MB | 83.18% | 0.828 |

Extension model (binary, Hinglish-aware): 470.6 MB → 118.4 MB with INT8 (75% smaller) and accuracy unchanged within 0.15 points (Hindi 85.1%, Hinglish 84.4%, English 96.7%, mixed 86.5%). On the frozen Hinglish conversational test, the gated window raises split-narrative detection from 28.9% (current message only) to 76.1%.

These five-class scores describe the synthetic distribution. A first zero-shot check on real conversation data (CAD, ConvAbuse, PRISM) gave AUROC 0.47 to 0.74 ([`thread_benchmark/external_eval/RESULTS.md`](thread_benchmark/external_eval/RESULTS.md)); the dataset is a controlled benchmark and training material to be mixed with real data, not evidence of real-world accuracy.

Every number is backed by a report file: `thread_benchmark/quant/int8_report.json`, `thread_benchmark/gru/out/benchmark_report.json`, `hinglish_context/codemix_eval/*.json`, `poster_v1/REPORTS/`. Details in [`thread_benchmark/RESULTS.md`](thread_benchmark/RESULTS.md).

## Dataset (included in this repository)

The complete five-class dataset is committed under [`thread_benchmark/dataset/`](thread_benchmark/dataset): 105,000 threads in 180 files (`len_{03,05,07,10}/{english,hindi_devanagari,hinglish}/{0_benign,...,4_predatory_grooming}/{train,val,test}.jsonl`), plus [`DATASET_CARD.md`](thread_benchmark/dataset/DATASET_CARD.md) and `MANIFEST.csv`. The same files are attached to the GitHub release as `surakshanet_thread_dataset_105k.zip`. The Hinglish and Hindi binary data used by the extension model are in [`hinglish_context/codemix_hinglish/`](hinglish_context/codemix_hinglish) and [`hinglish_context/macd_hindi_cache/`](hinglish_context/macd_hindi_cache).

## Reproducing the results

Tested with Python 3.12 and Node 22.12 on macOS (Apple silicon). The reported GPU run used one NVIDIA T4 (EC2 g4dn.xlarge). All commands run from the repository root.

**1. Environment**

```bash
git clone https://github.com/PrathamGarg1/surakshanet.git && cd surakshanet
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # pinned versions; boto3 is needed only for data generation
```

The base model `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` is downloaded from the Hugging Face Hub on first use.

**2. Prepare and check the dataset** (no generation needed; the data is in the repository)

```bash
python thread_benchmark/scripts/flatten_dataset.py
# expected output: train: 83672 threads / val: 10765 threads / test: 10563 threads
```

**3. Train, benchmark and stage the five-class models** (reported settings: 2 epochs, batch 32, max length 256, learning rate 4e-5, seed 42; about 20 minutes on one T4 for both models; resumable)

```bash
bash thread_benchmark/scripts/run_training.sh
```

This trains the last-message-only control and the thread model, runs `benchmark_v2.py` (accuracy and macro-F1 by length, script, class and on same-last-line pairs) and copies the models to `thread_benchmark/artifacts_v2/cloud_results/`, where the later steps read them. Expected: thread model about 97.96% accuracy / 0.980 macro-F1, last message only about 83.18% / 0.828. GPU training is not bit-for-bit deterministic, so expect differences in the last decimals. Note: the script overwrites `artifacts_v2/cloud_results/`.

**4. Frozen MiniLM + GRU**

```bash
python thread_benchmark/gru/embed_lines.py       # one embedding per line, cached in gru/cache/
python thread_benchmark/gru/train_gru.py         # writes gru/out/ (gru.pt, gru.json, benchmark_report.json); expected 0.9517 accuracy / 0.9522 macro-F1 in FP32
node thread_benchmark/gru/parity_test.mjs        # JavaScript runtime must print PARITY OK
```

**5. INT8 export and evaluation**

```bash
python thread_benchmark/quant/export_quantize.py   # thread_fp32.onnx 470.8 MB -> thread_int8.onnx 118.2 MB; encoder_int8.onnx
python thread_benchmark/quant/eval_quant.py        # writes quant/int8_report.json; expected 97.88% / 0.979 (thread INT8), 94.91% / 0.950 (GRU INT8)
```

`quant/latency.py` also needs the extension model of step 7 and measures single-request latency on your own CPU, so the numbers differ by machine.

**6. Real-data check (optional)**: `external_eval/eval_external.py` needs the third-party files CAD (`external_eval/data/cad/data/cad_v1_1.tsv`), ConvAbuse (`external_eval/data/convabuse.csv`) and PRISM (`external_eval/data/prism_cleaned.csv`), which are not redistributed here. Then run `python thread_benchmark/external_eval/eval_external.py`.

**7. Binary Hinglish-aware extension model (v2)**

- *Training (Modal account, T4, about 18 minutes of training).* One-time setup: `pip install modal && modal token new && modal volume create surakshanet-notebook`. Then `modal run hinglish_context/scripts/train_codemix_modal.py --mix shipped_v2` trains on Hindi (20,183) + Davidson (19,826) + Hinglish (18,920) messages for 3 epochs (batch 16, learning rate 2e-5), exports ONNX, quantizes to INT8 and evaluates. The `shipped_v2` preset reproduces the data protocol recorded in [`hinglish_context/codemix_eval/shipped_model_metrics.json`](hinglish_context/codemix_eval/shipped_model_metrics.json), the `metrics.json` of the model used in the extension; the script was edited after that run, so weights are not guaranteed to be identical. The notebook [`hinglish_context/notebooks/train_binary_codemix_modal.ipynb`](hinglish_context/notebooks/train_binary_codemix_modal.ipynb) is the earlier interactive version. The bundle lands in `extension_v2/assets/models/custom-macd-model-shipped_v2/`; copy it to `extension_v2/assets/models/custom-macd-model/` to use it.
- *Evaluation.* All reports used in the paper are in `hinglish_context/codemix_eval/`; `hinglish_context/scripts/` holds the scripts that produce them (`benchmark_narrative_kv.py`, `gate_v2_benchmark.py` to `gate_v4_realistic_bench.py`, audits). They read the model from `extension_v2/assets/models/custom-macd-model/`.
- *Gate logic check:* `node hinglish_context/scripts/test_narrative_cache.mjs`.
- *Build the extension:* place the model files (`config.json`, tokenizer files, `onnx/model_quantized.onnx`) in `extension_v2/assets/models/custom-macd-model/`, then `cd extension_v2 && npm ci && npm run build`. In Chrome open `chrome://extensions`, enable Developer mode, choose Load unpacked and select `extension_v2/dist/`.

**8. Paper** (`paper/`): with a current TeX Live (acmart 2.x): `cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main`. With Tectonic, whose bundled acmart is older, build a variant: `sed -e 's/\\setcopyright{cc}/\\setcopyright{acmcopyright}/' -e '/\\setcctype/d' main.tex > main_tectonic.tex && tectonic main_tectonic.tex`.

**What was run to check these steps.** On a fresh clone: environment install, step 2 (counts above), a 64-example smoke run of `train_v2.py`, ONNX export and INT8 quantization (470.8 MB to 118.2 MB), `parity_test.mjs` (PARITY OK), `test_narrative_cache.mjs`, `embed_lines.py --limit 200`, `npm ci && npm run build` of `extension_v2`, and the Tectonic paper build (7 pages). The full 20-minute training, the Modal training and the optional real-data check were not re-run for this commit; their reports are the ones stored in the repository.

Model weights (`*.onnx`, about 118 MB each) are not stored in git. Steps 3 to 5 produce the five-class ones and step 7 the extension one. The poster system (v1) is built with `npm ci && npm run build` inside `poster_v1/`; its training pipeline is `poster_v1/training/`.

## Notes on data and use

- The five-class dataset is synthetic (LLM-generated, checked by automatic rules, not by human annotators). It contains abusive, harassing and grooming-style text but no real people. Grooming threads use only non-sexual cues (secrecy, isolation, age probing). Use it only to build protective classifiers.
- `poster_v1/` and `hinglish_context/` are built on MACD (Gupta et al., NeurIPS 2022 Datasets and Benchmarks) and Davidson et al. (ICWSM 2017); `hinglish_context/codemix_hinglish/` is a machine-converted derivative of MACD. Check the original licences before redistributing.
- Parental login and Child Protection Mode of the poster system live on the branch `aamod/login-signup` and are not part of `main`.

## Authors

Pratham Garg, Aamod Jain, Geeta Yadav (IIT Ropar). Contact: 2023csb1147@iitrpr.ac.in
