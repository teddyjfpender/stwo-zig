# CAS09: two separate degree tracks through sparse-height FRI

**Status:** experimental native implementation and canonical byte proof,
stacked on CAS07/XDM05 and the one-height independent-track slice. No
production PCS selector, S31 key mode, release profile, or proven security
bits select this proof. The soundness theorem is open.

At each present source height `i`, the prover first commits the original
`M31` source columns under the single XDM05 transposed root. The transcript
then derives its OOD point and binds each claimed value before drawing one
batch challenge `lambda`. Two vectors are formed at that height:

```text
O_i(r) = Σ_j lambda^j f_(i,j)(r)
Q_i(r) = Σ_j lambda^j q_(i,j)(r)
```

`q_(i,j)` is the native conjugate two-point quotient computed from **that
same** original column and its OOD claim. The two vectors use the same column
power order, but never enter the same FRI word. At an absent height, both
vectors are zero. The height and its fold challenge remain in the schedule.

The prover executes the native circle-to-line first fold separately for `O`
and `Q`. At every later height it inserts the matching height vector into
the previous line track with the same native `insertCircleBatch` operation
used by CAS07. It commits **two** four-coordinate line Merkle roots after
each nonterminal fold, in original-then-quotient order, and reveals two
bounded terminal line polynomials. Transcript role tags include the height
and track before each root and terminal vector. `S31CAS09` version 9 has
canonical total length, profile, root, point, claims, nested XDM05 source
opening, both line openings at each level, and both terminal vectors.

The verifier selects the expected statement externally, checks the exact
byte shape, replays the transcript, authenticates the shared source rows and
**each** line tree, recomputes both original and quotient words from every
opened source pair, and checks both fold recurrences and both terminal
polynomials at every sampled projected query. This gives two native
whole-oracle degree-test paths rather than a single mixed original/quotient
batch. Each path still batches columns with a random `lambda`; a theorem is
required to turn that batching and the sparse query event into degree
soundness for every individual source column.

The focused gapped `H=4` proof contains a nonconstant top source, an absent
height, and two lower source heights. It produces and verifies versioned
proof bytes with matching final transcript states. The opt-in full-width
pilot uses the current Gate source **shape**: `k=20`, `H=17`, present heights
`0,2,4,6,11,12,16`, and counts `51,8,15,8,28,8,193`. Its 311 columns
share low-degree `x+constant` values per height. It therefore exercises the
full 193-column bucket and both tracks across all 17 folds, but it is **not**
the Gate AIR or witness generator. One ReleaseSafe run with 232 illustrative
queries took 4.64 seconds in the prover, 46.4 ms in verification, and emitted
1,706,048 proof bytes. A separate `/usr/bin/time -l` run of the test binary
reported 681,934,848 bytes peak resident memory (about 650.3 MiB) and
681,460,600 bytes peak memory footprint. These are one-run measurements, not
a performance bound or a certified security setting.

The remaining bridge is substantial: bind the actual S31 Gate key's four
challenge-dependent roots, all 319 committed columns and verifier-owned OOD
claims (311 trace columns plus eight composition columns) to this one-root
experimental source profile while preserving each root's original challenge
epoch; prove the normalized
source-height/lifted-row relation and the conjugate two-point circle-code
degree theorem; establish correlated cross-domain agreement and the
small-height condition; then derive a conservative adaptive BCS/ROM bound
for this **two-track** transcript at the selected `T=2^64` work-factor
target. The published one-batch Protocol 3 theorem cannot be assigned to
this changed two-track schedule without a new reduction. P05 and release
admission remain open.

Focused checks:

```sh
zig build --build-file src/prover/build.zig test-paired-independent-heights -j4 -Doptimize=Debug
zig build --build-file src/prover/build.zig test-paired-independent-gate-pilot -j4 -Doptimize=ReleaseSafe
```
