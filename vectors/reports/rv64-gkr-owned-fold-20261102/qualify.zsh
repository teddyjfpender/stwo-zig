#!/bin/zsh
set -eu
zig build test-native-cpu-gkr-rows -Doptimize=ReleaseSafe --summary all
zig build test-native-cpu-gkr-rows -Doptimize=ReleaseFast --summary all
baseline_dir=$(mktemp -d /tmp/rv64-owned-fold-reference.XXXXXX)
trap 'rm -rf "$baseline_dir"' EXIT
git archive 6091851f7 src/prover | tar -x -C "$baseline_dir"
printf 'pub const ForField = @import("lookups/gkr_prover.zig").ForField;\n' > "$baseline_dir/src/prover/gkr_capture_root.zig"
for mode in ReleaseSafe ReleaseFast; do
  zig test -O"$mode" --dep stwo_core --dep baseline -Mroot=src/prover/gkr_parallel_capture_root.zig --dep stwo_core "-Mbaseline=$baseline_dir/src/prover/gkr_capture_root.zig" -Mstwo_core=src/core/mod.zig
done
