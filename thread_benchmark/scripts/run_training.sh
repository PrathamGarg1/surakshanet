#!/usr/bin/env bash
# Exact settings of the reported GPU run (cloud/launch_train_ec2.sh): both models, then the benchmark.
# Run from the repository root:  bash thread_benchmark/scripts/run_training.sh
# Needs dataset/all/*.jsonl (python thread_benchmark/scripts/flatten_dataset.py). Resumable with --resume.
set -euo pipefail
cd "$(dirname "$0")"
export NO_LEDGER=1 TOKENIZERS_PARALLELISM=false
python -u train_v2.py --mode isolated --epochs 2 --batch 32 --max-len 256 --val-n 4000 --eval-batch 128 --workers 2
python -u train_v2.py --mode thread   --epochs 2 --batch 32 --max-len 256 --val-n 4000 --eval-batch 128 --workers 2
BENCH_BS=128 python -u benchmark_v2.py          # writes ../artifacts_v2/benchmark_report.json
# the export / evaluation scripts read the models from artifacts_v2/cloud_results/
mkdir -p ../artifacts_v2/cloud_results
cp -r ../artifacts_v2/model_isolated ../artifacts_v2/model_thread ../artifacts_v2/benchmark_report.json ../artifacts_v2/cloud_results/
