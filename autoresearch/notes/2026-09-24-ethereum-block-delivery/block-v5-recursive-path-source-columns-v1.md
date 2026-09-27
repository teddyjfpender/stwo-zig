# Direct recursive path/public/root source columns

This batch changes the canonical native and execution parent source path. Root
qualification passes32 focused ReleaseFast checks: seven new path/public/root
checks, earlier direct source checks, and actual assembled parent body generation.
The source hash receipt is `cpu-performance-gates-v1/direct-recursive-path-source-columns-qualified-v1.json`.
No STARK proof, guest, device, segment, or benchmark was run. These are source,
parity, mutation, allocation-failure and body-generation gates; they do not
qualify complete recursive proving performance.

## Wired changes

- `blake3_projection_links.buildColumns` emits cohort11 secure packing and cohort7
  affine index routes directly. Repeated trace logs share the same index producer
  and preserve their original multiplicities; chunk order, partial chunks, and
  query-bit read counts are unchanged.
- `blake3_opening_inputs.Builder.initColumns` emits sentinel2, byte10, packing11,
  readonly16, and adapter17 columns. Routing arrays and FRI wire plans are scratch;
  only the projection port/read metadata and committed columns survive preparation.
  FRI packing precedes projection packing exactly as in the dense oracle.
- `blake3_stark_paths.prepare` and `prepareMainColumns` select those owners by
  default. `prepareRows` is an explicit legacy oracle. Merkle geometry, root/path
  comparisons, path-use rollback on error, and fixed-path recipes are unchanged.
- Exact opening source tuples have separately allocated backing storage instead
  of belonging to the retained path arena. `blake3_native_openings.prepare`
  releases them only after complete typed Deep/FRI opening inventory admission.
  Tuple release leaves readonly, packing, byte, and adapter columns intact.
- `blake3_native_public_sources.prepare` directly emits cohort2 public coordinates
  and cohort12's sixteen published-sum limbs. It still invokes the canonical
  statement encoder and validates the public arithmetic owner/evaluation.
- Native and execution root/nonce source constructors directly emit cohort2
  root/key coordinates and cohort9 private root/nonce words. Reusable v5 adapters
  use bounded subviews and separately owned main-root columns, without flattening
  the source rows. Root/nonce receipts and pinned root checks remain mandatory.
- Final parent assembly freezes source cohort2 and cohort7 alongside the previously
  direct cohorts. The arithmetic input audit reads borrowed boundary columns. After
  that audit, the initial boundary domain is released while an expanded owner
  appends public lowering terms in the original order. Cohort2/cohort7 no longer
  retain the assembler's duplicate dense live/fixed row buffers.

Every direct emitter compares the compact fixed tail against the independently
constructed legacy fixed recipe. Optional owners are fully constructed before
publication; failure cleanup retains a single owner. The explicit dense source
APIs remain parity oracles. AIR equations, public terms, cohort ordinals, key
recipes, and typed verifier authority are unchanged.

## Nonproving qualification handoff

Root: `src/frontends/riscv/block_v5_recursive_path_source_columns_test_root.zig`.
Seven new tests in `recursion/air/blake3_path_source_columns_test.zig` cover:

1. Packing/byte/readonly/adapter/sentinel row and fixed-tail parity, duplicate
   trace rejection, source-mode mixing rejection, and tuple release after exact
   typed opening admission.
2. Every allocation failure during routing, emission, scatter, and publication.
3. Repeated projected logs, three query positions, multi-chunk affine links,
   partial packs, parity, mixed-source rejection, and allocation failures.
4. Fixed-tail mismatch, missing indexed rows, and publication/reuse rejection.
5. Root/nonce/joint-main parity, independent nonce change, omitted external key,
   checked prefix subviews, and every constructor/main-owner allocation failure.
6. Canonical nonzero register/sparse-memory public encodings, sixteen sum limbs,
   transcript-word mutation, mixed-source rejection, and allocation failures.
7. Actual typed captured path/oracle/public constructor body generation.

The root also imports earlier scalar/upstream/PCS tests and actual native,
execution, owned, and borrowed parent body fixtures. The source-only fixtures
construct arithmetic/routing inventories; they do not create fresh proof receipts.
No performance or full-proof qualification is claimed.

## Work/storage accounting and remaining materializers

For C trace columns, Q queries and F authenticated secure FRI group values, this
batch emits C sentinel rows, C*Q readonly and adapter rows, C*Q+F byte rows, and F
FRI pack rows. Shared projection rows add
Q*sum(ceil(log/4)) over distinct nonzero trace logs to each of packing and routing.
The temporary exact opening tuple roster has C*Q+4*F entries, is owned separately,
and is freed after opening coverage admission. Physical domain padding still
applies; direct columns are not free and this note makes no speedup claim.

ID14 is not complete. Genuine remaining canonical upstream materializers are:

- `blake3_stark_paths.Builder.live/fixed`: nonhash Merkle boundary, route, private
  word and select rows produced by group/frontier witnesses. The downstream
  assembler now scatters boundary/route directly but those upstream row buffers
  still exist until source release.
- `blake3_transcript_witness.Prepared`: transcript boundary, route, challenge,
  query-mask, retry-control, and counter rows. Final assembly has direct source
  cohorts but transcript emission still owns these upstream row buffers.
- Explicit dense graph/witness oracles, including `prepareRows`, remain intentionally
  available for independent parity. Caller-owned graph/evaluation arrays and
  compact path/hash metadata are still required by arithmetic and custody admission.

The next cohesive reduction should target those real Merkle/transcript nonhash
emitters, preserving exact schedules and independent fixed-tail recipes, rather
than claiming their final direct transpose eliminates upstream materialization.
