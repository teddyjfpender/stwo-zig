#!/usr/bin/env bash
# Paired, same-host CUDA experiment on the Rust-qualified contiguous PIEs.
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

for mode in batch batch-image; do
  options=()
  if [[ $mode == batch-image ]]; then options+=(--cuda-static-image); fi
  python3 "$root/tools/starknet-block-collector/circuit_pipeline.py" \
    --backend cuda-resident --cuda-batch "${options[@]}" \
    --sample-device-memory --adapted-dir "$adapted" \
    --circuit-prover "$prover" --expected-receipt "$reference" \
    --out "$output/$mode" \
    15627902-15627904 15627905-15627907 \
    > "$output/$mode-driver.log" 2>&1

  if [[ -n ${STWO_PINNED_CAIRO_VERIFIER:-} ]]; then
    python3 "$root/tools/starknet-block-collector/verify_cuda_cairo.py" \
      --proof-dir "$output/$mode" --receipt "$output/$mode/receipt.json" \
      --verifier "$STWO_PINNED_CAIRO_VERIFIER" \
      --out "$output/$mode/rust_cairo_verification.json" \
      > "$output/$mode-rust-verification.log" 2>&1
  fi
done

python3 - "$output" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
for mode in ("batch", "batch-image"):
    receipt = json.loads((out / mode / "receipt.json").read_text())
    print(mode, "wall_s", receipt["serial_wall_s"],
          "whole_device_peak_bytes", receipt["sampled_whole_device_peak_used_bytes"],
          "root_sha256", receipt["root"]["proof"]["sha256"])
    for leaf in receipt["leaves"]:
        print(" ", Path(leaf["pie"]).stem, "cairo_s", leaf["leaf_stages"]["cairo_prove_s"],
              "wrap_s", leaf["leaf_stages"]["wrap_s"],
              "static", leaf["cairo_static_phases"])
PY
