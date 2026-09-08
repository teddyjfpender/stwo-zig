# Small native and recursive proof loop

The CPU and Metal routes use one guest fixture, native Poseidon protocol,
canonical serialization, and fresh CPU native verification. Both then run the
same 39-component, 47-domain CPU outer proof. This is the existing q1/native,
q3/outer development profile, not the secure CSP profile or a detached root.
Native producer allocations are destroyed before decoding its proof. The outer
verifier still requires the separately admitted native input.

## Fast semantic gate

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-poseidon-merkle -Doptimize=ReleaseSafe --summary all
```

This checks scalar/SIMD permutation and leaf parity, every layer of mixed-domain
and streaming Merkle trees, and scratch allocation failure cleanup. It avoids
compiling the native and recursive prover graphs.

## Complete CPU proof

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe \
  --summary all -- --native-steps 64 --native-backend cpu
```

Sizes are 1, 4, 16, and 64 instructions of the same finite counter-loop ELF.
`--check-workload` validates all execution prefixes and their 16-cycle
continuations without proving. Omitting arguments runs the broader mutation and
downstream replay gate. The continuation defines the fixture endpoint; this
example proves the first child, not a pair of children or a whole block.

## Complete proof with Metal native proving

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe \
  --summary all -- --native-steps 64 --native-backend metal \
  --aot-bundle /absolute/path/to/core-v2-bundle \
  --aot-manifest-sha256 MANIFEST_SHA256
```

The runtime admits the pinned `core_v2` AOT bundle, checks actual Poseidon device
dispatch, and shuts down before fresh CPU verification and outer construction.
A missing/mismatched bundle fails before proving. CPU builds do not import Metal.
The retained local `.git/local-ethereum/aot-m4` bundle and its digest are recorded
in the September 8 native fixed-cost evidence. They are local artifacts, not a
portable dependency. To produce a bundle elsewhere:

```sh
python3 scripts/zig_serial_build.py metal-core-aot -Doptimize=ReleaseSafe
zig-out/bin/metal-core-aot build --output-dir /absolute/new/bundle
```

## Measurements and memory ladder

Build once, then use `scripts/riscv_small_recursive_benchmark.py --binary PATH
--backend cpu --out NEW_DIRECTORY`. It runs three fresh processes per instruction
size, retains logs/binary hashes, and checks complete-proof success. Metal also
requires the two AOT arguments above. Complete-request time includes process
startup, runtime initialization, both proofs and verification, and teardown;
compilation is separate. Source patches captured by the runner describe the
invoking worktree; retain the corresponding build log/source receipt to bind an
older binary to its build source.

For the separate memory ladder, select `--memory --sizes 1 4 16`. The runner uses
64 instructions in every case while varying distinct word addresses touched.
It independently checks each load/store and final state, including a store
pending across the 16-cycle continuation. `--check-memory-workload` runs those
execution and corruption checks without proving.

For diagnostic runs, set `STWO_RISCV_NATIVE_PROFILE=1`, `STWO_ZIG_PCS_TIMING=1`,
and `STWO_ZIG_PCS_COLUMN_HISTOGRAM=1`. CPU/Metal composition timing is available
through `STWO_ZIG_RISCV_CPU_COMPOSITION_TIMING=1` and
`STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING=1`. Stage/task recording can perturb
scheduling, so the repeated timing runner removes diagnostic flags. Do not add
overlapping worker spans to coordinator wall time.

Native allocator counters cover caller-allocator payload, excluding size-routed
Merkle mmap buffers and device allocations. Process RSS is recorded separately;
task reservations and source/LDE payload estimates are not measured live memory.

The unchanged 16-case CPU/Metal CSP comparison now lives in
`scripts/riscv_csp_paired_benchmark.py`. Its clean snapshot inputs, workers=16,
secure protocol, alternating rounds, fresh verification and per-case identity
checks remain required. A repeated latency or memory regression blocks promotion.
