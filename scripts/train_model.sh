#!/usr/bin/env bash
#
# Train a model on a generated dataset and print its evaluation.
#
#   scripts/train_model.sh
#   scripts/train_model.sh --accounts 2000 --split temporal
#
# Generates a dataset with labels, trains, evaluates, and prints the metric set
# together with what the metrics do not mean.
#
# Read that last part. The generator plants the typologies the rules look for,
# so a score from this pipeline measures agreement between the generator and
# the model. It is a real check that training works end to end and no evidence
# at all about detection quality on a real portfolio. docs/model-card.md is
# blunter about it.
set -euo pipefail

cd "$(dirname "$0")/.."

ACCOUNTS=1000
SPLIT="grouped"
SEED=42
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --accounts) ACCOUNTS="$2"; shift 2 ;;
    --split) SPLIT="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

case "$SPLIT" in
  grouped|temporal|random) ;;
  *) echo "--split must be grouped, temporal or random" >&2; exit 64 ;;
esac

if [[ "$SPLIT" == "random" ]]; then
  echo "warning: a random split puts four accounts of a five-account ring in" >&2
  echo "         training and the fifth in test. The score it reports is how" >&2
  echo "         well the model memorised that ring." >&2
  echo >&2
fi

OUT="${OUT:-data/generated/train-seed${SEED}}"

echo "generating a labelled dataset"
python3 scripts/generate_data.py \
  --accounts "$ACCOUNTS" \
  --transactions "$(( ACCOUNTS * 40 ))" \
  --complaints "$(( ACCOUNTS / 4 ))" \
  --seed "$SEED" \
  --with-labels \
  --out "$OUT"

echo
echo "training and evaluating (${SPLIT} split)"
python3 scripts/evaluate_model.py --dataset "$OUT" --split "$SPLIT" --seed "$SEED"

echo
echo "dataset kept at ${OUT}. It is reproducible from --seed ${SEED}, so delete"
echo "it rather than committing it."
