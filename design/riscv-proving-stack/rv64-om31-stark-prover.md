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
one column at a time. Its lazy quotient provider uses bounded row scratch and
`core.pcs.ForField(OM31).quotients` as the formula authority. It does not build
a lifted copy of the entire M31 trace. This first wide route prioritizes
correctness and ownership; it is not a throughput qualification. Compact
coefficient-backed quotient inputs require a separately admitted expansion
lease and currently return an explicit unsupported error. Existing QM31
optimized sampling and quotient paths remain selected for the default field.

Device stages, secure capabilities and work-capture hooks that still encode
QM31 are not silently reused. Unsupported explicit wide execution requests
fail. Wide role integrations should provide the typed native domain callback;
that callback may itself use packed M31 evaluation and packed OM31 weighting.

## Evidence and limits

The combined Safe/Fast gate executes eleven tests, including five new OM31
cases and five retained QM31 full-prover cases. It covers actual fresh receiver
acceptance, every allocation failure in the tiny full pipeline, an invalid
Boolean witness, six proof mutations and the full fold-step 4 path. Mutations
exercise high-coordinate main/composition OODS values, an opening, a main root,
a high-coordinate terminal value and composition sample shape. The captured
historical QM31 LS20/tail18 proof remains byte-identical at 381,800 bytes and
is accepted by a separately launched receiver.

The resource follow-up makes GKR allocation failures propagate as
`OutOfMemory`; structural shape errors remain distinct. The exhaustive GKR
lifecycle test now checks those exact errors instead of normalizing them.

This is an actual native typed-proof qualification. Ethereum retained-block
proving over OM31, a durable wide wire codec, optimized wide capability paths,
GPU execution and outer recursive-proof qualification are separate gates. No
production default changed, no speedup is claimed, and the whole-protocol
128-bit security policy remains fail closed until its complete requirements
are established.
