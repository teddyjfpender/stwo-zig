#!/bin/zsh
set -eu
zig build test-native-cpu-wide-sampling -Doptimize=ReleaseSafe --summary all
STWO_ZIG_BENCH_WIDE_SAMPLING=1 zig build test-native-cpu-wide-sampling -Doptimize=ReleaseFast --summary all
zig build test-native-cpu-om31 -Doptimize=ReleaseSafe --summary all
zig build test-native-cpu-om31 -Doptimize=ReleaseFast --summary all
