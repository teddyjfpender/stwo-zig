# Session 12: SN2 constraint cumulative parity

Date: 2026-07-25

## Scope

This increment builds the exact differential required by Session 11. It
compares the cumulative four-coordinate composition accumulator produced by
the authenticated CUDA AOT bodies with a fixed four-lane Zig SIMD oracle after
every canonical constraint part in
`vectors/cairo/sn_pie_2_composition.bin`.

This is constraint-evaluation evidence. It does not claim an SN PIE proof,
proof-byte parity, or proving latency.

## Exact fixture

The fixture preserves all semantics used by the generated constraint bodies:

- 58 components in canonical composition order;
- 279 canonical component/instance/part placements;
- 1,325 ordered random coefficients;
- exact component trace spans and preprocessed-column indices;
- exact base and extension parameter sources;
- exact denominator inverses;
- exact trace, evaluation, and constraint domain log sizes;
- exact circle-offset addressing;
- all four QM31 accumulator coordinates.

The differential is bounded to the public core's fixed four-lane SIMD type,
so fixture bytes do not depend on the build host's suggested vector width.
Eight full-height
constant palette columns retain the real offset-addressable geometry through
the largest `2^24` evaluation domain without materializing the recorded SN2
trace. Per-component trace-offset and interaction-offset tables map the exact
logical sources into that palette. This makes the fixture synthetic but not a
different evaluator or a reduced placement inventory.

Fixture facts:

- SIMD lanes / CUDA rows: 4
- Maximum addressable rows: `2^24`
- Arena words: 134,266,566
- Device arena bytes: 537,066,264 (512.19 MiB)
- Evidence-run fixture header SHA-256:
  `7e535000e96a896469755761dd48d5692423429fe8f01ecf044d1bb1bbef816a`
- Repository-normalized fixture header SHA-256:
  `583a9d20b8f540c71d8840f9025122dd1b022fa11b7ae3a374e161016c1cea20`
- Oracle zero-inversion failures: 0

The checked-in fixture removes trailing spaces from generated array rows; its
C values are identical to the evidence-run fixture. The deterministic generator
recompiles through the repository's canonical named module graph and reproduces
the normalized checked-in header byte for byte.

## Device contract

`tests/cuda/native_cairo_eval_sn2_parity_smoke.cpp` uses the production native
AOT loader. For every placement it:

1. Uploads the exact 96-byte `StwoCairoEvalArgs` binding.
2. Resolves the body by authenticated cache key, schema, and kernel name.
3. Requires `module_globals = none` and a verified cubin digest receipt.
4. Launches only the four bounded rows while retaining the real logical row
   count and domain geometry.
5. Synchronizes and reads the cumulative four-coordinate accumulator.
6. Compares every row and coordinate with the Zig SIMD oracle.
7. Stops at the first mismatch and reports component, instance, part, row,
   coordinate, expected value, and actual value.

The terminal telemetry contract is exact:

- AOT loads: 271
- AOT cache hits: 8
- AOT misses: 0
- Launches: 279
- Launch failures: 0
- Runtime compiles: 0
- CPU fallbacks: 0

There is no NVRTC or source-JIT entry point in this smoke.

## Host evidence

Passed:

- deterministic four-lane fixture generation with zero inversion failures;
- byte-for-byte fixture reproduction;
- `python3 -m unittest scripts.tests.test_cuda_cairo_eval_aot`;
- `python3 -m unittest scripts.tests.test_cuda_build`;
- `python3 scripts/check_source_conformance.py`;
- Zig formatting checks;
- focused SN2 fixture deep gate: 18/18;
- filtered deep graph compilation and execution through the recorded-witness
  matrix test.

The filtered deep gate reached 18/20 passing tests. Its remaining two failures
are concurrent Pedersen capability expectation changes outside this slice:
one registry test still expects `module_globals = none`, and one alias-drift
test expects `StrictAotViolation` rather than the now-earlier
`InvalidKernelDescriptor`. The new parity modules no longer create duplicate
module ownership: every core field dependency uses the public
`stwo_core.fields.*` surface.

## Device evidence

The strict-AOT differential passed on the locked RTX 4090 with CUDA 12.8:

```text
SN2 constraint parity passed: components=58 placements=279
aot_loads=271 cache_hits=8 missing=0 runtime_compiles=0 cpu_fallbacks=0
```

The run used an isolated 319-entry authenticated carrier:

- 48 released Native AOT modules;
- 271 exact Cairo constraint bodies;
- released archive SHA-256:
  `bbf7426d3e988dbc35a1e777e9d1855c607936e1ab8a8b490da5c773d49a08c2`;
- released archive build identity:
  `72a2dee34a879e6ca76d206b372912a488a0540daef4d34aefd077791fe4f66c`;
- isolated combined AOT pack SHA-256:
  `4ec38eeb4dafd3a1da349e0b016434a5c30e96a6313a5e9cabaf09b929105f29`;
- parity executable SHA-256:
  `07b14b85182ce52efb630b74325ec96881648df95e1613801c1ba82c5701ec94`.

The released archive was not rewritten. A new authenticated lookup object
resolved both its 48 frozen cubins and the 271 separately compiled SM89
constraint cubins, so the device evidence cannot hide a runtime compile or
silently replace the released Native runtime.

## Evidence boundary

This establishes cumulative CUDA constraint-evaluation parity for all 279 SN2
placements on the bounded four-row fixture. It does not establish recorded
SN2 witness completion, interaction-trace parity, commitment parity, proof
bytes, full SN PIE proving, or proving latency. Those remain separate gates.
