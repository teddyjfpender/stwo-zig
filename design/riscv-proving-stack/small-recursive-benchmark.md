# Small native and recursive proof loop

The small detached route now proves both segments of a completed memory
workload using CPU or Metal native proving, followed by CPU outer proving.
A separate verifier checks both serialized proofs, exact coverage, memory and
clock continuation using explicit keys and expected public inputs. This is a
verified proof bundle in the q1/native, q3/outer development profile; succinct
parent recursion and production-security measurements remain pending.

Current retained evidence and rejection cases are indexed in
[the detached-route progress report](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/progress.md).

## Complete detached proof gate

Build the producer and verifier once:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  build-recursive-segment-v2-concrete-outer-proof \
  build-recursive-segment-v2-detached-verifier -Doptimize=ReleaseSafe --summary all
```

Then generate both children, wait for producer destruction and process exit,
and check acceptance plus tampering in fresh verifier processes:

```sh
proof_bins=src/integrations/riscv_cpu/zig-out/bin
proof_evidence=vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1
proof_output=.git/local-riscv-proving-stack/detached-cpu-example
python3 scripts/riscv_segment_v2_detached_gate.py \
  --producer "$proof_bins/recursive-segment-v2-concrete-outer-proof" \
  --native-backend cpu --initial-memory-word 13 \
  --verifier "$proof_bins/recursive-segment-v2-detached-verify" \
  --bundle "$proof_output/child-0" \
  --key-sha256 a0c39b4d4fcc7f94cd37d62dd671f90bfc778cb879bff29ea7bbdd2172539aaa \
  --expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-0-expected-wire.json" \
  --other-expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  --adjacent-bundle "$proof_output/child-1" \
  --adjacent-key-sha256 02697d47111fa4cec96b3c2d701f59940eb070d8b94a9c45d63db8f331f20517 \
  --adjacent-expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  --output "$proof_output.json"
```

Choose a new output path for each run. Key pins and expected statements above
come from independently retained admission for this exact fixture; the command
never trusts newly produced admission files. A circuit change must be admitted
separately before replacing these pins.

The current command uses reviewed seed13 admission after dynamic memory ranges
and selectors were added. Seeds13/14/269 have fresh CPU proof evidence under
the same per-child keys; arbitrary address topology is a separate admission.

For Metal, build the same producer target under `src/integrations/riscv_metal`,
use that directory's installed producer with `--native-backend metal`, and add
`--aot-bundle PATH --aot-manifest-sha256 SHA256`. Keep the CPU verifier and the
same independent pins and expected statements. The gate checks real Metal
dispatch for both children. AOT generation is described below.

Omit `--producer` to replay existing artifacts without taking the heavy-job
lock. This keeps the small verification loop usable during a separate build.
The retained complete commands passed all 17 cases in 8.076 seconds on CPU and
6.282 seconds with Metal native proving. These are development observations,
excluding compilation, and do not establish a production-security benchmark.

## Retained native-assisted benchmark route

The earlier CPU and Metal measurements below use one guest fixture, native Poseidon protocol,
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
64 instructions in every case while varying 1/4/16 distinct word addresses,
initially zero and spaced 128 bytes apart. The ELF length stays fixed. This
changes sparse memory paths as addresses increase; initializing the same
contiguous words in every case would conceal that cost.
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
