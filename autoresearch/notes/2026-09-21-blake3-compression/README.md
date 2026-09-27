# Typed BLAKE3 arithmetic foundation — 2026-09-21

Continues the user's prioritized BLAKE3 migration. The preceding goal turn was
progress: it implemented a CPU protocol suite, verified PCS/FRI integration and
measured native hashes. This turn adds the canonical compression schedule and a
typed arithmetic reference needed for the recursive provider.

Implemented:

- Shared G operation schedule used by native execution, typed definition and
  witness generation; six binary modular additions and four XOR/rotations.
- Seven rounds, BLAKE3 message permutation, initialization, counter, block
  length, flags, feedforward, and optional 56-call native trace.
- A degree-two typed G reference with 704 Boolean inputs/witness columns and
  1024 equations. All 32-bit quantities are losslessly represented. Carry
  equations have integer sums <=3, so M31 cannot hide an integer overflow.
- Semantic identity pinned to
  `381e79c61735c9bb5926647c7566b1cb5b5a102cc26b3f3a7c8d5e7f598f6f8c`.

Validation: four guarded tests pass in 626 ms, compilation 4 seconds.
Checks include degree analysis, 32 edge/random G inputs, each of 704 positions
mutated by a bit flip and by setting it to 2 (1408 rejected witnesses), all 56
G calls from a compression with a nonzero high counter, and standard-library
hash parity for lengths 0..64 plus 65,127,128,1023,1024,1025,2048. These latter
checks exercise partial/full blocks, chaining values, chunk counters and parent
root compression. The standard-library hash is an independent implementation;
the earlier foundation also checked it against 35 official hash vectors.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-compression -Doptimize=ReleaseSafe --summary all
```

Scope: the typed component constrains G arithmetic. The native compression
schedule and recorded call connections are not yet authenticated by a recursive
AIR. This is deliberately an arithmetic oracle, not the final wide production
layout. No production recursive key, call relation, Metal provider or proof was
changed. No new speedup is claimed.

Next: pack bounded limbs and XOR/rotation lookup providers using this reference
as the equivalence oracle; authenticate initialization, per-round message
selection, state transitions and feedforward. Then constrain complete BLAKE3
framing/chunk trees, transcripts and Merkle paths before selecting new trusted
protocol/key identities. Do not treat native witness generation or G correctness
as proof of these remaining connections.

Original persistent-plan, scheduling, fused-PCS, direct-layout and parameter
requirements remain unfinished and active; hash migration has user priority.

Source conformance remains at 103 existing findings, with unchanged finding
identities; it is not green. `git diff --check` passes.
