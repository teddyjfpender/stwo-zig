# Actual field-selected STARK prover

The explicit OM31 path now proves a real M31 AIR and is accepted by a freshly
initialized core OM31 full-STARK receiver. The test is a nonconstant 16-row
Boolean trace constrained by `f * (f - 1)` over its trace zerofier, rather than
a mock composition value. Two constraints exercise secure random weighting;
all eight composition coordinates are committed and sixteen split composition
columns are sampled. The main OODS evaluation is checked to use the upper half
of the extension. Both FRI fold-step 1 and fold-step 4 complete end to end.

Receipts and reproduction commands are under
`vectors/reports/rv64-word16-execution-20261101/om31-stark-prover-v1/`.

## Integration contract

```
const Engine = prover.engine.ForField(OM31).ProverEngine(CpuBackend, H, MC, Channel);
const Scheme = prover.pcs.ForField(OM31).CommitmentSchemeProver(CpuBackend, H, MC);
const Components = prover.air.component_prover.ForField(OM31);
const Domain = prover.air.accumulation.ForField(OM31);
```

Use `core.channel.raw_mod_m31.Om31Channel` with the corresponding raw Merkle
channel adapter. Domain/OODS component bindings use the same field-selected
vtable authority; `core.air.derive.ForField(OM31).ComponentAdapter` builds both
sides. `Trace` and its polynomial ownership remain M31. The existing QM31
entrypoints remain facades of their default field family.

Ordinary CPU column preparation, interpolation, commitments, retained trees,
opening machinery and storage remain shared M31 code. Secure composition,
OODS points and values, quotient arithmetic and FRI select the extension
explicitly. FRI receives a Merkle-only typed adapter and calls the shared core
wide folding authority. Legacy QM31-specific CPU/device folding hooks are not
reinterpreted as OM31 operations.

The wide sampling fallback borrows retained M31 coefficients or interpolates
one column at a time. Its lazy quotient provider now supports compact and
hybrid retained/compact storage. It combines coefficients into numerator groups
per sample batch, column height and representation, then evaluates only those
aggregate polynomials with the same pooled M31 executor used by the default
field. Row finalization uses `core.pcs.ForField(OM31).quotients` as the formula
authority. It never reconstructs or retains source-column LDEs and introduces
no process cache. Existing QM31 optimized sampling and quotient paths remain
selected for the default field.

`Scheme.wide_quotient_group_byte_limit` admits the checked aggregate evaluation
and conservative distinct-height twiddle footprint before those buffers are
materialized. Refusal is `QuotientScratchBudgetExceeded`, a resource refusal.
`Provider.resourcePlan()` exposes the group count and buffer bounds. Metadata
and small row workspace remain charged to the caller allocator; this cap is
not a whole-prover or RSS bound. The path qualifies ownership and correctness,
not production-scale throughput.

Device stages, secure capabilities and work-capture hooks that still encode
QM31 are not silently reused. Unsupported explicit wide execution requests
fail. Wide role integrations should provide the typed native domain callback;
that callback may itself use packed M31 evaluation and packed OM31 weighting.

## Evidence and limits

The latest combined Safe/Fast gate executes fourteen tests: six full OM31
STARK cases, two wide constant-accumulator cases, five retained QM31
full-prover cases and the discovery root. It covers actual fresh receiver
acceptance, every allocation failure in the tiny full pipeline, an invalid
Boolean witness, six proof mutations and the full fold-step 4 path. Mutations
exercise high-coordinate main/composition OODS values, an opening, a main root,
a high-coordinate terminal value and composition sample shape. The captured
historical QM31 LS20/tail18 proof remains byte-identical at 381,800 bytes and
is accepted by a separately launched receiver.

The resource follow-up makes GKR allocation failures propagate as
`OutOfMemory`; structural shape errors remain distinct. The exhaustive GKR
lifecycle test now checks those exact errors instead of normalizing them.

This is an actual native proof qualification. The wide durable wire codec and
fresh receiver roundtrips are separately qualified, and current compact gates
compare its exact bytes. Ethereum retained-block proving over OM31, optimized
wide capability paths, GPU execution and outer recursive-proof qualification
are separate gates. No
production default changed, no speedup is claimed, and the whole-protocol
128-bit security policy remains fail closed until its complete requirements
are established.


## Mixed-height correction

The initial wide fallback omitted per-column point folding when sampling
committed M31 polynomials. Uniform-height proofs did not expose the error.
An integration test with real ALU roles at logs5/6 failed at FRI with
`InvalidLastLayerDegree`; an independent two-role Boolean AIR reproduced the
same failure without the GKR binding adapter.

The sampler now evaluates each polynomial at
`point.repeatedDouble(lifting_log_size - column.log_size)`, matching the legacy
sampler, core DEEP preparation and receiver. The independent mixed-role proof
passes complete fold-step1 and fold-step4 pipelines, with separate fresh
verification. No column height or core quotient formula was changed. A second
regression checks that constant-only composition writes every coordinate of
the selected extension; the former four-coordinate loop now uses `DEGREE`.

Before/after logs and the expanded fourteen-test Safe/Fast gate are pinned in
`om31-stark-mixed-v1/`. Real mixed ALU+GKR integration has its own physical
proof gate; the tiny baseline does not substitute for that gate.


## Compact-owner qualification

`om31-compact-prover-v1/` records complete compact, retained and hybrid storage
comparisons. For fold1 the uniform and mixed proofs are respectively3316 and
6364 bytes; for fold4 they are3328 and7780 bytes. Compact and retained encodings
are byte-identical, as are the hybrid mixed-height encodings. Decoded compact
and hybrid proofs are accepted by independently initialized receivers. The
registered Safe/Fast gates also inject every allocation failure through the
compact full pipeline and test explicit scratch-budget refusal. These small
examples establish protocol parity; they are not Ethereum throughput or GPU
memory measurements. The compiler MaxRSS shown in build logs is not prover
peak memory.
