# RAM LogUp width: degree-four triple range batches

Status: geometry and authority design only. No equation, transcript, claim
layout or proof protocol has been changed for this proposal.

## Exact current inventory

`block_v7_ram_component_v1.zig` has 24 fixed, 88 main and 116 interaction
columns. The 29 secure interaction planes contain:

| Physical planes | Typed obligation | Fractions per plane |
|---|---|---:|
| 0 | Guest RAM transitions | 2 |
| 1 | Ordered cohort link, including incoming edge | 2, plus its constant |
| 2 | First-touch interval membership | 2 |
| 3–26 | Range16 requests | 2 |
| 27 | First-touch census | Polynomial count |
| 28 | Range-request census | Polynomial count |

Each of the two RAM lanes contributes 17 original word ranges and seven
initialization ranges. Thus the 24 range planes encode exactly 48 fractions,
including all original signs, multiplicities and conditional gates. The first
10 original ranges per lane have degree-one weights; the remaining seven
word ranges and seven initialization ranges have degree-two weights. All
range denominators have degree one in trace cells.

The component's existing expansion is two bits and its admitted equation
degree is four. This is required by direct RAM/initialization/halt equations
and the ordered link term; it is not available for arbitrary degree growth.

## Minimal candidate

Keep the transition, link, interval and both census planes separate. Flatten
only the range fractions in canonical order `(range_index, lane)` and group
three consecutive fractions into each of 16 planes. No cross-relation mixing
or public aggregate splitting is permitted.

For `d_i = A*x_i - z`, weight `w_i`, and normalized cumulative difference
`delta`, the three-fraction equation is:

```
delta*d0*d1*d2 - w0*d1*d2 - w1*d0*d2 - w2*d0*d1 = 0
```

The cumulative term has degree four. Since every weight has degree at most
two, each numerator term also has degree at most four. The same expansion
therefore suffices. Four fractions would require degree five and increase the
quotient domain; that is not the candidate.

| Geometry | Current | Candidate |
|---|---:|---:|
| Range planes | 24 | 16 |
| Total physical secure claims | 29 | 21 |
| Interaction M31 columns | 116 | 84 |
| Total fixed/main/interaction columns | 228 | 196 |
| Direct equations | 132 | 132 |
| Total equations | 161 | 153 |
| Degree / expansion bits | 4 / 2 | 4 / 2 |

Interaction width decreases 27.59%; total column area decreases 14.04%.
At log22 this saves 536,870,912 bytes of native coefficients and 1,073,741,824
bytes of blowup-one LDE storage per equal-sized cohort. Those are calculated
payloads, not measured peak or timing. Existing coefficient-only storage must
not count both savings as resident memory after LDE release.

Each RAM component also removes 64 QM31 OODS samples (32 columns, current and
previous masks) and 32 M31 leaf words per query. Tree count, height, security
configuration and query count remain unchanged. Actual recursion arithmetic
and hash-row savings need capture measurements; no speedup is inferred from
column count alone.

## Compute tradeoff and exact factoring

A naïve triple residual performs more general extension-field products per
range family than the current pair residual. Width reduction is not a free
compute reduction. The shared range challenge provides a useful exact form.
With arbitrary actual secure `A` and `z`—without assuming `A=1`—the pair is:

```
D2 = A²*x0*x1 - A*z*(x0+x1) + z²
N2 = A*(w0*x1+w1*x0) - z*(w0+w1)
residual = delta*D2 - N2
```

For triples define base-field symmetric terms:

```
s1 = x0+x1+x2
s2 = x0*x1+x0*x2+x1*x2
s3 = x0*x1*x2
n2 = w0*x1*x2+w1*x0*x2+w2*x0*x1
n1 = w0*(x1+x2)+w1*(x0+x2)+w2*(x0+x1)
n0 = w0+w1+w2
D3 = A³*s3 - A²*z*s2 + A*z²*s1 - z³
N3 = A²*n2 - A*z*n1 + z²*n0
residual = delta*D3 - N3
```

The base coefficients can be computed in packed M31, with cached secure
challenge powers and secure-by-base products. Only the final delta product
needs general QM31 multiplication. This is an evaluation optimization, not a
new constraint, and can first be checked on today's pair equations without
changing proof bytes. Triple batching still requires a new admitted layout.

## Required authority and implementation changes

1. Introduce a versioned, independently selected RAM interaction layout. Bind
   it into source entry identity/first channel and joint layout identity.
   `block_v7_memory_source_v1.zig` currently uses explicit version-two tags;
   the standalone bundle statement also pins `24,88,116,161,4,2`. Do not silently
   reinterpret these old identities or cached keys.
2. Add a complete canonical 48-entry range manifest. Its lane, source index,
   sign and polynomial weight must be covered exactly once. The remaining
   relation categories cannot be merged to conceal compensating claims.
3. Make the new witness context return triple fractions for the range planes.
   `block_v7_memory_trace_v1.interactions` already consumes `termsAt` generically,
   but `RamContext.termsAt` and `R.Term` currently expose pair-specific types.
   Keep providers' original pair/census semantics unchanged.
4. Native prover and verifier must absorb **all 21 physical claims** before
   interaction commitment. Normalization remains one claimed sum per physical
   accumulator, divided by the original row count. No aggregate-only framing.
5. Replace hardcoded closure slices in memory source, bundle, and
   `block_v7_memory_claim_closure_v1.zig`: range becomes `[3..19]`, first-touch
   census index19, range census index20. Transition/link/interval remain0/1/2.
   Preserve the original event-count ×24 range bound; batching does not reduce
   the number of actual range requests.
6. Independently recompile recursive original equations and public layouts.
   `recursion/air/block_v7_memory_composition_v1.zig` currently fixes a
   29-claim prefix and explicit offsets. Candidate public width is76 instead
   of84: prior21, first30, last41, boundary flags52/53, prior ordinal54, halt58.
   Shape, public bus, transcript, DEEP/FRI, cold key and live capture must all
   use that same new layout; old claim frames cannot be relabeled.
7. Thread the selected layout through separate cohorts, joint memory,
   heterogeneous original union, bounded codecs/checkpoints, resource models,
   and complete native/recursive receivers. Existing input fixed/main trees
   may remain mathematically identical but metadata must bind the new layout.
8. The current optimized tile/packed-base evaluator explicitly assumes116
   interaction columns and161 equations. Parameterize it only through the
   independently admitted finite layout; preserve the original pair mode as
   the differential oracle until the new original and complete roots qualify.

## Qualification before adoption

- Symbolic degree and exact 48-entry coverage tests, including missing,
  duplicate, wrong-sign and wrong-gate entries.
- Scalar, packed, common-challenge-factorized and recursive equation parity.
  Non-base OODS values use the full extension-field algebra, never the base
  evaluator; both forms must be polynomially identical.
- Compare semantic typed totals with the pair oracle on genuine sorted RAM
  witnesses. Proof bytes necessarily change with the new layout; semantic
  and ordinary-verifier agreement replace old-byte equality for this step.
- Reject physical-claim compensation, shifted public offsets, stale layout
  identifiers/keys, old proofs, changed first/last boundaries and wrong census.
- Fresh standalone originals, separate cohorts and a complete root with all
  producers destroyed; independently derived recursive fixed rows/keys.
- Measure source generation, interaction commitment, quotient, OODS/DEEP/FRI,
  opening time and phase live memory. Include full canonical security before
  selecting the new layout in production.
