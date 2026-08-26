# P-003 exact main-witness field work

Status: production-complete for the shared CPU/Metal RISC-V frontend.

## Boundary

`main_witness_field` counts logical M31/QM31 work performed while Tree 1 is
materialized and its fixed-table multiplicities are assembled. It includes:

- all 17 typed opcode witness and lookup-entry schedules;
- program, memory, Merkle, and clock materialization row authority;
- program, memory, clock, and guest-caller fixed-table requests;
- enabled direct semantic audits; and
- exact dense counter-set reductions for the worker geometry that ran.

Sparse-memory and guest-provider Poseidon permutations are deliberately not
charged here. They are the separately tracked
`sparse_memory_and_guest_poseidon_witness` P-003 family. This separation avoids
double charging the same permutation when the combined Poseidon2 route builds a
caller projection and provider trace together.

## Source authority

`main_witness_work.Authority` schema v2 derives the base schedules by executing
the generic typed lookup, semantic, program, memory, and clock builders with a
counting scalar. Its source digest binds every opcode authority digest, the
guest-extension manifest digest, schedule algorithm versions, fixed-table
geometry, and the derived operation counts.

The guest caller executes 224 additions, 288 multiplications, and one batch
inversion per active row. Transactional caller lookup registration executes 251
additions and 36 multiplications per active row: one checked pass, one mutation
pass, and exactly 115 successful dense-table coefficient updates. Provider
Poseidon work remains excluded by construction.

## Producer routes

- The bounded prepared epoch gives every graph task an exclusive receipt shard.
  The seal merges only completed shards, validates row/cardinality shape against
  the authenticated plan and statement, and publishes the receipt only after
  the epoch reaches its publication barrier.
- The predecessor producer publishes the actual opcode counter-reduction count
  and whether its conditional semantic audit ran. An opt-in, allocation-free
  second pass over immutable execution rows then issues the same source-bound
  receipt; it does not infer worker or audit geometry from ambient state.
- The combined Poseidon2 producer extends that predecessor receipt with the
  caller projection and transactional caller lookup work.
- The split Poseidon2 prepared producer counts the lookup work it actually
  executes over the already-published caller columns. It reports zero caller
  projection rows rather than claiming work performed by the detached shadow
  owner.
- Test-only forged-row fallback paths remain explicitly fail-closed because
  their rescan/drop schedule differs from production ingestion.

## Performance discipline

Ordinary proofs do not initialize a work authority, allocate receipt shards, or
branch inside a row loop. Prepared production retains one null `WorkState`
pointer when capture is disabled. The predecessor result adds only the two
producer facts needed for exact optional capture: counter-set merge count and
audit execution. Profiling scans completed rows after production, never during
the hot write loop.

The measured prepared fixture also exposes backend-sensitive work honestly:
each additional dense counter-set reduction costs exactly 2,981,888 M31
additions. After subtracting those real reductions, N=1/2/4 operation receipts
are identical.

## Evidence

On the reconciled 2026-08-20 source, the focused Debug main-trace
plan/production gate passes 318/318. The tranche-local counts below record the
earlier acceptance run and are retained as historical evidence.

- Main-trace production, Debug: 313/313 tests pass.
- Main-trace production, ReleaseFast: 313/313 tests pass.
- Split Poseidon2 exact-receipt gate, Debug and ReleaseFast: 1/1 passes; the run
  portion is below one second in both modes.
- Combined Poseidon2 end-to-end proof receipt, Debug and ReleaseFast: 1/1 passes;
  the shipping-mode proof run is approximately three seconds on the capture
  host.
- Backend-contract dependency gate: 24/24 tests pass.

Two focused integration targets now isolate the extension edit loop:
`test-main-witness-poseidon2-receipt` and
`test-main-witness-poseidon2-combined-receipt`.
