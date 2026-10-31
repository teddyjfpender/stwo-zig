# Word16 common composition geometry review

Read-only review of the current full Word16 execution roster and core lifted
PCS. This is a source-level algebra review, not a new protocol qualification.
No degree declarations or evaluator equations were changed for this review.

## Findings

Deleting the non-DIV/MUL bound increment while retaining composition split two
is not admitted by the current trace/OODS geometry. Nor can DIV/MUL simply
select split one while retaining their existing native quotient evaluators.
The source couples each role's quotient expansion to the common split through
circle-point doubling. The component override validates integer metadata; it
does not establish that an arbitrary override preserves this coupling.

`word16_execution/components.zig:geometryOverride` uses common split two and
raises every degree-three role's declared bound by one. The producer wrapper
in `prover/air/component_prover.zig` then activates **true polynomial extension**
for those roles. It does not rerun their native AIR callbacks at twice the row
count. DIV/MUL already evaluate at four times their native trace height.

## Exact coordinate identity

Write `D(p)` for circle doubling, `l` for a component trace log, `s` for its
native quotient expansion log, `C` for the common composition log, and `S` for
the common composition split. Current trace/OODS mask log is `G=C-S`.

The default accumulator lift (`prover/air/accumulation.zig:liftedValueAt`)
repeats the bit-reversed evaluation index. Algebraically, the contribution of
an intrinsic quotient polynomial `q` is

    q(D^(C-l-s)(p)).

The PCS samples each native trace polynomial at
`D^(G-l)(p)` (`prover/pcs/sampled_values.zig:evaluateTreesSequential` and
`sampled_coefficient_plans.zig`). Component OODS denominators use exactly this
same local point (`rv64/air/geometry.zig:localPoint`, `denominatorInverse`).
Therefore the OODS authority expects

    q(D^(G-l)(p)).

These agree directly when `s=S`. For degree-three components `s=1`, the current
bound override causes polynomial interpolation and zero extension from log
`l+1` to `l+2`, preserving `q` as a polynomial. The subsequent default lift then
uses `C-l-2=G-l`, matching the split-two OODS point. This explains why a genuine
polynomial extension, rather than a repeated-index lift, is necessary.

A counterexample to removing this normalization is the nonconstant quotient
`q(p)=p.x`. A one-doubling mismatch replaces a coordinate `u` by `2*u*u-1`.
Their difference `2*u*u-u-1` is not the zero polynomial. Requiring only that a
small component's declared bound lie below the largest CPU bound does not
repair this identity. Native DIV/MUL point callbacks use the ordinary local
point and vanishing polynomial, with no compensating factor or coordinate
change.

`prover/air/component_prover_test.zig` already independently compares a widened
nonconstant polynomial at an arbitrary OODS point and explains why a repeated
index lift fails. Its split-only mock validates callback routing, not a theorem
that every real component may change quotient split without normalization.

## The two suggested changes

1. **Split two, all bound deltas zero.** With CPU log22 and intrinsic bound23,
   the common bound can fall to23, so `compositionMaskLogSize` becomes21.
   `geometry.localPoint` rejects global log21 for CPU trace log22. The legacy
   RV64 PCS lane has no revision override to raise that mask log independently.
   Simply raising the trace-mask log would also require changing composition
   reconstruction: `proof.extractCompositionOodsEvalWithSplit` currently receives
   `mask_log+split`, and smaller committed chunks are sampled after PCS folding.
   One cannot change just the host admission check.

2. **Common split one, all bound deltas zero.** CPU log22 gives common bound23
   and mask log22, so the first guard is satisfied. However, a native DIV/MUL
   quotient at log `l+2` contributes `q(D^(21-l)(p))`; its OODS callback expects
   `q(D^(22-l)(p))`. This is the explicit one-doubling counterexample above.
   Keeping its callback and all claims intact does not make this a valid proof
   route, even if the arithmetic provider is very small.

Under this periodic lifted PCS, the high-degree component's OODS polynomial is
composed with `D^(G-l)`. That composition scales its degree with the global
trace height. Small native height therefore does not, by itself, eliminate its
higher-degree contribution to the common composition polynomial.

## FRI and memory accounting

The current prover uses `C=max(component bound)` and enforces equal common
splits (`core/air/components.zig`). It interpolates one secure composition of
size `2^C`, then commits `2^S` secure chunks, each native log `C-S`.

The PCS FRI bound is selected from the largest **sampled committed column**
(`core/pcs/verifier.zig:computeLiftingLogSize`), including CPU trace columns;
it is not automatically the unsplit composition log. CPU log22 remains the
largest trace degree if composition chunks fall from log22 to21. Thus the
suggested change does not establish a twofold FRI-height reduction.

If all participating providers genuinely admitted degree-three/2n authority,
common split one could use a size-2n composition and two secure chunks of size
n instead of size-4n and four chunks. This would halve that composition
workspace/interpolation and its committed-column count. CPU and other native
2n evaluations would remain unchanged, and FRI would still include CPU log22.
Whole-job savings require measurement; composition is only one stage.

## Experiment and acceptance gates

A separate experimental protocol may first demonstrate the expected failures
above using a nonconstant MUL and DIV witness, unequal provider/CPU logs, and
arbitrary-Q OODS replay. Empty/dummy arithmetic providers can conceal the
coordinate error and are insufficient controls.

The useful engineering route is to inventory genuine quartic residuals and
make all providers degree three, or design a separately reviewed multi-domain
composition protocol. Metadata-only bound reduction is not that protocol.
For a degree-three provider route, retain the existing control, then qualify:

- dense arbitrary-Q degree and native/Packed/Circuit residual parity;
- complete valid witnesses and independent OODS receivers with real MUL/DIV;
- exact local/global claim closure, altered bounds/split/root/claims rejection;
- unequal native logs and serial/parallel/prepared/backends/failure ownership;
- q70/P26 fresh receivers and retained packet semantic endpoints;
- matched source counts, stage timings and RSS, without claiming native FFT or
  FRI work that was not removed.

A new geometry authority must be transcript-bound before roots/randomness,
including common split and each role's bound/normalization. Review the concrete
`word16_execution/protocol.zig:mix`, its global-execution manifest/request digest
(which delegates to it), and stage-one worker resume identities. Immutable
fixed-column trees may be reused if their program, widths, logs and hash suite
are unchanged; cached component/receiver/circuit layouts may not reuse the old
geometry identity. Proof/receipt version pins, composition column counts,
reconstruction factors and any future recursion topology admission must follow
the new authority. Existing legacy recursion source was not changed or newly
qualified by this review.
