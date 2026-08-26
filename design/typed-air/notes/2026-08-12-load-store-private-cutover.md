# LOAD_STORE private fixed-authority cutover

Status: family-private implementation complete; shared production integration
is deliberately deferred to the serialized integration lease.

## Authority

- Canonical identity:
  `143d0a41d92b67babe31a8006ee8df8a553aa0db3a249d28ce32584c8abe1b4e`.
- Exact geometry: 48 main columns, 62 semantic roots plus placement (63
  direct constraints), 16 ordered lookup events, lookup batch size 2.
- `fixed_load_store.zig` retains the legacy polynomial construction order
  exactly. Symbolic replay creates zero additional DAG nodes and randomized
  QM31 evaluation agrees root-for-root and event-for-event with the legacy
  oracle.
- The retained binding and authority are pointer-free. The evaluator performs
  no allocation, arena traversal, string lookup, callback dispatch, or dynamic
  recipe interpretation.
- The authenticated authority owns address formation, the 24-bit base and
  22-bit aligned-address proof bounds, alignment, signed and unsigned loads,
  byte/half/word stores, partial-word preservation, x0 discard, witness
  projection, direct roots, and ordered lookup construction.
- The binding digest is recomputed at compile time; malformed semantic,
  witness, direct-recipe, lookup, and batching fields fail closed.

## Soundness and completeness receipts

- Every legal I/S encoding is admitted exhaustively: 33,554,432 combinations
  across all 4,096 immediates and all relevant register fields.
- The full 131,072 `opcode[6:0] × funct7 × funct3` selector matrix is checked
  against the decoder and exact word reconstruction.
- Architectural retirement exhausts every byte value at every offset for
  signed/unsigned loads and every byte-store source; every halfword value at
  both aligned offsets for signed/unsigned loads and stores. This is 657,408
  independently calculated load/store retirements in addition to word,
  negative-immediate, alias, x0, alignment, and field-alias boundaries.
- Honest rows are validated through the generated witness and fixed AIR.
  Mutations of result, memory value, preservation, address, predecessor clock,
  and control state reject before the first column write.
- Authority construction is covered by exhaustive allocation-failure cleanup.

## Failure-atomic retirement

- Exact I/S word admission precedes all logical mutation.
- The protocol order is fixed as `rs1` first, then load destination/store
  source, then aligned memory. Aliases advance through distinct subclocks.
- Staging snapshots CPU, sparse-memory word and initialization state, trace,
  register clocks, memory clocks, and first-access baseline state.
- Capacity growth is followed by full stale-state revalidation. A deliberately
  re-entrant allocator mutation is detected before publication.
- Cold allocation failures leave CPU, architectural memory, trace rows,
  accesses, and clock-update logs unchanged. Capacity and a newly materialized
  zero page are the only permitted logically invisible residue.
- A warmed 1,024-store run succeeds with every later allocator request forced
  to fail. The store path skips reserve helpers once trace, tracker maps/lists,
  initialized-word metadata, and the sparse page are ready.
- Exact pointer-free footprints are 88 bytes for `Plan` and 16 bytes for
  `Prepared`; these are compile-time caps, not descriptive estimates.

An independent adversarial review additionally closed two boundary gaps:

- `inst_word` and the decoder's overlapping I/S fragment fields are now
  reconstructed at the witness boundary; unused load-`rs2` and store-`rd`
  values are canonical zero rather than unconstrained trace metadata;
- plans snapshot all three append-only tracker-log lengths, so unrelated log
  mutation during reserve or between prepare and commit fails stale instead of
  being silently interleaved with the transaction.

## Performance receipts

ReleaseFast paired medians use 13 alternating fixed/legacy samples and retain
the shared strict `fixed × 0.97 <= legacy` regression floor.

- Direct AIR focused repeats: 1.0042x, 1.0041x, 1.0045x. The fixed core is at
  parity with the already-tight legacy arithmetic and does not regress it.
- Lookup construction focused repeats: 2.5749x, 2.5872x, 2.5329x.
- Retirement focused repeats: 1.0978x, 1.0994x, 1.0946x.
- The final private gates pass in all modes: Debug 226/226, ReleaseSafe
  226/226, and ReleaseFast 229/229. The final ReleaseFast paired sample measured
  1.0026x direct, 2.4266x lookups, and 1.1580x retirement.

The measurements justify the design honestly: the principal AIR win is
removal of generic lookup-building overhead, while retirement gains come from
fixed scalar planning, capacity-aware warm paths, and non-allocating atomic
publication—not from changing protocol geometry or weakening checks.

## Shared integration boundary

The serialized production owner must route LOAD_STORE through the pinned
authority in main trace, interaction trace, formal extraction, and generated
retirement; remove the private root; retain the old semantic module solely as
an explicitly named test oracle; make legacy execution fail closed; and rerun
the complete AIR, runner, formal, rigidity, exact proof, live Sail, source
singularity, and stabilized performance gates.
