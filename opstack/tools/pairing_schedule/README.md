# Complete BN254 pairing positive-delegation candidate

This directory is a source-derived design and independently evaluated Python
integer oracle. It does not add an ISA tag, guest feature, AIR, worker, proof
admission or host-authorized validity bit. It is independent of the current
dense/sparse field-provider implementation. Run the bounded oracle with:

```sh
python3 opstack/tools/pairing_schedule/oracle.py --repo . \
  --census /path/to/heavy-pairing-census-lru-final.json \
  --out /tmp/complete-pairing-positive-schedule.json
```

It evaluates one retained four-pair request, not a heavy block replay. The
committed receipt includes that public request so its arithmetic test is not
lost with the scratch census. No whole-protocol security certification is made.

## Existing semantics that must survive

Source authorities are `kona/src/precompiles/pairing.rs`, `pairing_miller.rs`,
`pairing_hint_stream.rs`, `pairing_residue.rs`, and vendored Ark BN254 parameters.
The current cache is execution-owned exact bytes, not a host-provided result
cache. Its 16-point LRU owns validated G2 points and prepared lines; grouping
only combines already-validated G1 contributions with exactly the same G2.
Every G2 is validated even when its paired G1 is infinity. Result caching does
not authorize a new input by hash equality. The hint stream advances its call
ordinal before cache/fallback handling and only proves a positive result.

Six 32-byte big-endian coordinates per pair must each be strictly less than
Fq's modulus. G2's wire order is x.imag, x.real, y.imag, y.real. The all-zero
coordinate pair denotes infinity. Nonzero G1 must satisfy y²=x³+3. BN254 G1 has
cofactor one. Nonzero G2 must satisfy the fixed twist curve and the actual
subgroup check `[6*x*x]Q = psi(Q)`, with source-fixed twist/Frobenius constants.
G2 curve membership alone is insufficient. Malformed counterpart coordinates
cannot be skipped because the other point is infinity.

This strict EVM coordinate boundary differs from the existing raw-u256
arithmetic service (0x40001), which intentionally reduces its field operands
modulo p. Delegating arithmetic is not delegating EVM input validity. Reusing
that service does not establish canonical pairing inputs.

## Positive-only first scope and fallback

The proposed single guest call consumes the original EVM calldata pointer,
pair count and a bounded optional positive witness. It returns a *fastpath
accepted* status, not an unconstrained EVM Boolean. Status one is legal only
when all canonicality, point, subgroup, line and residue obligations below
hold. The guest may then return EVM true. Status zero supplies no pairing
result: the original complete guest implementation executes, preserving false,
malformed, missing-hint and unsupported-large-request behavior. It must not be
interpreted as EVM false. Gas/length/error handling remains the guest's existing
precompile logic. Selecting zero may waste time; it cannot skip fallback.

The existing hint trailer already contains call-ordinal-indexed positive
witnesses, not a host correctness assertion. A future ABI may read this bounded
private hint as provider advice rather than marshal 960 bytes through guest
field routines. Either choice must bind the actual call ordinal/input bytes to
the CPU OWNER boundary. Malicious advice may force a fallback or an unsatisfied
fastpath proof, but can never elect a wrong successful result. Large (>16-pair)
requests must continue to fall back unless a new independently bounded class
is qualified. Empty input and infinity-only inputs are true only after all
present coordinates have been validated.

A universal provider additionally needs the full final-exponentiation result,
its zero/one checks, and a constrained non-one witness for false. A positive
residue witness by itself cannot prove false. The Python universal path uses
a generic exact exponent as a reference; this is not an optimized universal
AIR proposal. Positive-only deliberately avoids adding that false-result AIR.

## Source-owned typed microprogram

One request frontier authenticates each original coordinate byte and the final
accepted status, exact pair count, epoch/tick/call ordinal and execution tag.
Internal SSA values are Fq, Fq2, Fq6, Fq12 and affine/homogeneous point types;
read/write tuple namespaces include request ID, type, source instruction ID,
value ID and all canonical limbs. No global CPU Wire crossing occurs for each
Fq or Fq2 operation. Unit input ownership and full byte/multiplicity closure
remain mandatory. Temporary values and prepared lines are local to this proof.

The frozen macro schedule is:

1. Canonical-decode all six Fq coordinates for every pair, derive the exact
   infinity flags, then check both points and G2 subgroup membership.
2. Starting from Q, derive every prepared line with the original homogeneous
   double/add equations. The 65 signed Ate digits give 64 doubles, 21 signed
   additions and two ordered Frobenius correction additions: **87 lines per
   nonzero group**. Prepared lines are proved outputs, never host-authorized
   inputs. Zero/infinity selection, exceptional branches and exact point
   equality all require explicit constrained selectors in an AIR.
3. Check a canonical Fq12 seed `w` and inverse `v` with `w*v=1`. This proves
   nonzero w. Run the same signed Miller schedule seeded with w: 64 squares,
   21 signed multiplications by w/v and 87 sparse034 line steps per group.
4. Multiply the result by `w^(p³) * v^(p²) * w^p * c`, where c is represented
   as Fq6 embedded in Fq12. Require every resulting coordinate to equal one.
   Frobenius is a source-fixed linear map with checked constants.

Let `L=p³-p²+p+6x+2`, `E=(p¹²-1)/r`. The checked equation is
`z*c*w^L=1`, where z is the *authenticated* ordinary Miller product of valid
subgroup points. Since r divides L, E is a multiple of p⁶-1 and w is nonzero,
raising to E gives z^E=1. The Fq6 c representation is essential; allowing
arbitrary Fq12 c would make the check vacuous. The source parameter generator
checks the integer divisibility/coprimality assumptions. A proof of these
relations does not prove that arbitrary host-supplied z was a pairing: the
point/line/Miller bindings are inseparable obligations.

`loop_program` emits typed immutable square/seed/line instructions. Its
interpreter only accepts the exact source schedule for the validated group
count and seed mode. The oracle's generic tower implementation uses independent
Python modular arithmetic, and independently recomputes the full final
exponent for one real four-pair request and positive/negative controls. It is
an arithmetic/schedule oracle, not an AIR or an in-circuit soundness proof.

## Concrete work and crossing ledger

The retained independently collected heavy census has **84 calls, 336 pairs,
84 true results, no false/invalid requests, 87 distinct G2 encodings**, and no
result-cache hits. The selected first real four-pair request passes both the
generic final-exponent and positive-residue oracles. Its conservative schedule
has 256 preparation doubles, 84 signed preparation additions, eight correction
additions, 348 line products, 64 dense squares and 21 seed products. Lowering
this oracle's algebra literally produces:

| Phase | Fq mul | Fq add | Fq sub |
|---|---:|---:|---:|
| Input validity/subgroup | 15,528 | 9,544 | 19,748 |
| Prepared lines | 12,340 | 14,056 | 15,284 |
| Hint inverse | 75 | 122 | 123 |
| Seeded Miller | 33,867 | 52,826 | 53,259 |
| Residue tail | 363 | 530 | 567 |
| Total | 62,173 | 77,078 | 88,981 |

The 780 affine inverse witnesses in input validation are checked by product
relations already included in mul counts. Hint generation and generic final
exponent reference work are excluded from this positive-provider ledger. The
oracle deliberately uses full Fq12 products for sparse lines and affine scalar
arithmetic; these are conservative scheduling choices, not the existing
optimized Rust counts. It has no arbitrary advice-dependent constant folding.

This is **228,232 scalar result operations per four-pair call**. A naive
one-current-style-carried-row-per-result translation is not a speed result:
even assuming only 370 MAIN +48 local binding columns and packing four calls
per log20 proof, 21 such proofs would touch **9,204,400,128 cells** before
input frontiers, branch selectors, fixed columns and any further providers.
This conditional estimate is not a qualified width/bound; it demonstrates why
blindly moving the current arithmetic into one new precompile is insufficient.
Fused Fq2/tower identities, projective subgroup arithmetic, source-bound
point/preparation reuse and the dedicated dense provider must reduce real
rows/facts before production engineering. Each claim must include actual
padding, local GKR facts, openings and recursive graph costs.

At the external boundary, this corpus contains 8,064 input u64 words
(336*192/8) and at most 336 output words if every EVM result writes 32 bytes.
This excludes packet fields, alias-induced transitions and hint RAM if hints
are explicitly loaded through RAM. A direct frontier removes the nominal
22,185 existing sparse-line call boundaries and 331,163 current Fq2 service
boundaries **only for work actually moved into this provider**, replacing them
with 84 pairing request boundaries. It is not a claim that all 331,163 Fq2
calls in the execution belong to pairing, or that other field services vanish.

Current 238,226,172-retirement source attribution has disjoint function-self
buckets totaling 107,085,268 for Fq6 mul, Fq2 add, G2 preparation/subgroup/double,
Fp12 square, Miller wrapper and Fq2 square. These are concrete optimization
addresses, **not** a proven removable count: field routines can have non-pairing
callers and generic memcpy/memcmp self time is not fully assigned to pairing.
No new guest-retirement saving has been measured by this prototype. Existing
22,185 line calls and dense/factor caches must not be counted twice against
already-qualified earlier guest reductions.

## Remaining gates before admission

- Freeze a bounded ABI/status/error contract and CPU OWNER/frontier source
  authority, including every pair byte, ordinal, count, alias and zero-length
  behavior; implement actual guest fallback selection and byte-level oracle
  agreement on true/false/invalid/max-size requests.
- Derive a complete immutable low-row arithmetic DAG and range/carry degree
  bounds, local typed SSA closure and exact per-role GKR/binding authority.
  Source-code macros or the oracle's checked branches are not constraints.
- Bound local fraction multiplicities below the base-field characteristic
  and within the 128-target assumption ledger. Shard schedules before a large
  BYTE/SSA relation can wrap. Independently account for every positive/negative
  fraction and pole; no global point cache may be trusted by metadata alone.
- Prove exact canonicality, infinity equivalence, subgroup, prepared recurrence,
  twist orientation, source loop, nonzero inverse, Fq6 scale and all terminal
  equations. Include forged on-curve non-subgroup and valid-counterpart-infinity
  physical proofs, wrong line/seed/scale/call IDs, truncated inputs and cross-call
  balanced debts. True arithmetic evaluation alone does not close any bus.
- Qualify source-derived fixed geometry, native full RAM/OWNER closure and
  fresh independent receiver, followed by recursive source capture/leaf/root.
  Count native cells, all padded local facts and lifted opening width. Keep
  128-bit target under documented assumptions / security_qualified=false.
- First measure one representative full positive request and mixed fallback
  workload. No heavy block rerun or claimed end-to-end multiplier is authorized
  by this model. The previous CPU/R6/R7 controls and default guest remain intact.
