#!/usr/bin/env bash
set -euo pipefail

s31_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$s31_dir/../../.." && pwd)"
trials="${S31_TRIALS:-5}"
sizes=("$@")
if [ "$#" -eq 0 ]; then sizes=(256 1024 4096 8192); fi

cd "$repo_root"
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
zig build stwo-cairo-cpu -Doptimize=ReleaseFast
cargo build --release --locked --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml

for rounds in "${sizes[@]}"; do
  case_dir="$repo_root/zig-out/s31/scale/$rounds"
  python3 "$s31_dir/generate_scale.py" "$rounds" "$case_dir"
  scarb --manifest-path "$case_dir/cairo/Scarb.toml" build
  rm -f "$case_dir/cairo-input.json"
  "$repo_root/tools/stwo-cairo-vm-adapter-rs/target/release/stwo-cairo-vm-adapter" run \
    --program "$case_dir/cairo/target/dev/s31_square${rounds}_cairo.executable.json" \
    --program-type executable --arguments "$case_dir/cairo/arguments.json" \
    --prover-input-out "$case_dir/cairo-input.json"
  zig build --build-file src/frontends/s31/build.zig install -Doptimize=ReleaseFast \
    "-Ds31-source=$case_dir/square${rounds}.s31.json" "-Ds31-name=square${rounds}"
  python3 "$s31_dir/measure_scale.py" "$rounds" --trials "$trials"
done
