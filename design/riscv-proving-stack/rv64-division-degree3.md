# Independently sized DIV native2n route

`delegations/division/degree3_component.zig` is a separate concrete component.
The existing `division/component.zig` remains the legacy4n authority and its
standalone protocol remains unchanged. This is a component foundation, not a
CPU-ingress proof, full-ISA execution integration or full-block certificate.

The new component delegates all OODS, mask and arithmetic-lane evaluation to
the existing division component/provider. It changes only its declared bound
to trace-log+1, composition split to one, and its native domain loader to two
bounded n-point cosets. Its domain kernel loads16 rows of M31 input at once,
uses PackedM31 for local arithmetic and PackedQM31 for lookup algebra and
random-coefficient accumulation. OODS remains QM31 (or the explicit circuit
lane). A73856-byte heap scratch holds the packed physical row, keeping that
wide input off a256KiB worker stack. The shared coset helper retains expansion two as its
legacy default; only its explicit degree-three constructor selects two parts.
No DIV/REM architectural semantics, main hints, lookup tuples or interaction
witness equations were copied or changed.

## Degree inventory

All1567 residuals are at most cubic after the existing DIV-only inflation.
That inflation sets MUL selectors to literal zero, including the potentially
quartic signed-high MUL terms in the shared product evaluator.

- Bit/selector/sign booleans, count, padding and carry restrictions are degree2.
- Product operand selection and all schoolbook output equations are at most3.
- Sign/absolute-value corrections and quotient/remainder policies are at most3.
- In particular, `quot*sign_a*sign_b`, `negate*zero*quot`, and
  `enabled*(1-zero)*(remainder+gap+carry-divisor)` are cubic.
- The typed operand/result denominator is affine. Its inverse and prefix
  equations have degree at most2.

A dense test supplies independent affine lines through every main, fixed,
interaction and predecessor coordinate over the full QM31 extension. Every
fourth finite difference vanishes, and a third difference is nonzero. Actual
2n quotient interpolation and independent OODS verification additionally pass.
This is tested evidence plus source inspection, not a formal security proof.

| Per native DIV row | Legacy4n | Explicit degree3 |
|---|---:|---:|
| Fixed/main/interaction M31 columns |3/1135/8|3/1135/8|
| Constraints |1567|1567|
| Native evaluation rows |4n|2n|
| Common composition split |2|1|
| Current polynomial cells evaluated |4584n|2292n|
| Bounded scratch M31 cells |1151n|1151n|

The five predecessor columns are the main count and four final-prefix
coordinates. Partner-coset reuse keeps both routes bounded. Main, interaction,
lookup query mass and OODS masks are unchanged. No runtime or peak-RSS
improvement is claimed from these counts, and this slice does not change the
full Word16 roster or its common composition geometry.

## Closed qualification protocol

The standalone fixture uses a separate transcript tag and binds expected typed
requests as full-width canonical fields before roots/challenges. Its fixed root
comes from independently reconstructed geometry; its single physical claim
must equal the receiver's rational sum over expected requests. All claims are
transcript-bound before interaction commitment. Configuration is fixed q70/P26.
The CLI receiver uses its own pinned17-request fixture, never producer-supplied
`requests.json`. The public native API accepts independently expected typed
requests; it is not an accepting open-debt API.

The17-request fixture includes all eight DIV/REM opcodes, divide-by-zero,
signed overflow, negative remainders, W sign extension and full-u64 operands.
Source main can be released after commitment while narrow request metadata
survives to construct interactions. Tests cover changed expected requests,
physical claims/fixed roots/prefixes/count samples, false-result prover
rejection, empty padding, zero-pole transactional retry, all1567 scalar/PackedM31/
PackedQM31 residuals, real CircuitLane challenge/count/claim mutations, and
bounded two-part coset values/predecessors against a full2n FFT oracle.
Allocation-failure coverage checks initialization and each per-part FFT.

Legacy q70/P26 regeneration is byte-identical to the retained64-request control
(305888bytes, SHA256 f63f6818f90d9b12ddfb5f188e1d7983a3ec889f3ce304a29ee07316eea3c25b).
The new17-request proof has a different statement/protocol; its size must not
be used as a same-input compression benchmark. Pins and gate logs are in the
qualification report.


The former scalar2n loader exists only behind test-only compile-time entrypoints;
there is no production runtime fallback. Full q70 proofs from the packed path
match the scalar reference byte-for-byte at1,3 and16workers with256KiB stacks.
Current row evaluation is serial SIMD. The supplied pool parallelizes column
FFTs, not row blocks; these parity gates are not row-parallel speed evidence.
Heap-scratch/output/FFT allocation failures are exhaustively checked.


The stack qualification additionally dispatches the actual component domain
callback through a WorkLease onto a real256KiB helper thread. It asserts that
the helper ID differs from the caller, passes no pool inside that callback,
and compares every finalized quotient coordinate against direct caller
evaluation on nonconstant maximum-native-degree polynomials. ReleaseSafe and
ReleaseFast both pass. This tests the domain/row authority itself; it does not
infer its stack bound from the separate FFT-worker proof-parity tests or claim
that the entire prover can execute on a256KiB stack.
