#!/usr/bin/env bash
# Same-host ABCCBA CUDA experiment on the Rust-qualified contiguous PIEs.
# Build the resident product and generate the canonical preprocessing artifact
# before invoking this script. All proof files and logs remain under OUT_DIR.
set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 ADAPTED_DIR OUT_DIR" >&2
  exit 2
fi
: "${STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS:?set the absolute canonical artifact path}"
if [[ ! -f "$STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS" ]]; then
  echo "canonical preprocessed artifact is missing" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
adapted=$(cd "$1" && pwd)
mkdir -p "$2"
output=$(cd "$2" && pwd)
prover=${STWO_CIRCUIT_CUDA_PROVER:-$root/zig-out/bin/stwo-circuit-recursion-cuda}
reference="$root/vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json"
if [[ ! -x "$prover" ]]; then
  echo "resident CUDA prover is missing: $prover" >&2
  exit 2
fi
command -v nvidia-smi >/dev/null
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

for trial in serial-1 batch-1 batch-image-1 batch-image-2 batch-2 serial-2; do
  case $trial in
    batch-image-*) options=(--cuda-batch --cuda-static-image) ;;
    batch-*) options=(--cuda-batch) ;;
    serial-*) options=() ;;
  esac
  python3 "$root/tools/starknet-block-collector/circuit_pipeline.py" \
    --backend cuda-resident "${options[@]}" \
    --sample-device-memory --adapted-dir "$adapted" \
    --circuit-prover "$prover" --expected-receipt "$reference" \
    --out "$output/$trial" \
    15627902-15627904 15627905-15627907 \
    > "$output/$trial-driver.log" 2>&1

  if [[ -n ${STWO_PINNED_CAIRO_VERIFIER:-} ]]; then
    python3 "$root/tools/starknet-block-collector/verify_cuda_cairo.py" \
      --proof-dir "$output/$trial" --receipt "$output/$trial/receipt.json" \
      --verifier "$STWO_PINNED_CAIRO_VERIFIER" \
      --out "$output/$trial/rust_cairo_verification.json" \
      > "$output/$trial-rust-verification.log" 2>&1
  fi
done

python3 - "$output" <<'PY'
import json
import statistics
import sys
from pathlib import Path

out = Path(sys.argv[1])
samples = {}
for trial in ("serial-1", "batch-1", "batch-image-1", "batch-image-2", "batch-2", "serial-2"):
    receipt = json.loads((out / trial / "receipt.json").read_text())
    variant = trial.rsplit("-", 1)[0]
    samples.setdefault(variant, []).append(receipt["serial_wall_s"])
    print(trial, "wall_s", receipt["serial_wall_s"],
          "whole_device_peak_bytes", receipt["sampled_whole_device_peak_used_bytes"],
          "root_sha256", receipt["root"]["proof"]["sha256"])
    for leaf in receipt["leaves"]:
        print(" ", Path(leaf["pie"]).stem, "cairo_s", leaf["leaf_stages"]["cairo_prove_s"],
              "wrap_s", leaf["leaf_stages"]["wrap_s"],
              "static", leaf["cairo_static_phases"])
for variant, values in samples.items():
    print(variant, "median_wall_s", statistics.median(values), "samples", values)
PY
