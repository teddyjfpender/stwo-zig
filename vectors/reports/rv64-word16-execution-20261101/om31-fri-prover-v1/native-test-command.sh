#!/bin/sh
set -eu
zig test -O"${1:-ReleaseSafe}" --dep stwo_core --dep stwo_prover_engine --dep stwo_cpu_backend -Mroot=src/tests/native/prover/om31_fri_test.zig -O"${1:-ReleaseSafe}" -Mstwo_core=src/core/mod.zig --dep stwo_core -Mstwo_backend_contracts=src/backend/mod.zig --dep stwo_core -Mstwo_prover_api=src/prover_api/mod.zig --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api -Mstwo_prover_engine=src/prover/mod.zig --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api --dep stwo_prover_engine -Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig
