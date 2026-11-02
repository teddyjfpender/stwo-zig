#!/bin/zsh
set -eu
zig build test-riscv64-classic-witness -Doptimize=ReleaseSafe --summary all
zig build test-riscv64-classic-witness -Doptimize=ReleaseFast --summary all
zig build test-riscv64-truth-parallel -Doptimize=ReleaseSafe --summary all
zig build test-riscv64-truth-parallel -Doptimize=ReleaseFast --summary all
# Optional shared-host synthetic640-inverse kernel comparison, never a block claim:
# lockf -k /private/tmp/stwo-rv64-perf-heavy.lock env STWO_ZIG_BENCH_CLASSIC_WITNESS=1 zig build test-riscv64-classic-witness -Doptimize=ReleaseFast --summary all
