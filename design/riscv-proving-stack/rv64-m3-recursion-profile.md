# RV64 recursion M3 version: outer PCS profile `m3_b4_q51_p26_fold4` and 4-ary folds

Status: candidate recursion version (stream `recsize`, branch `codex/rv64-m3-recsize`).
**OFF by default.** With no environment selection every outer proof, digest, node
identity, tree.json, and root is byte-identical to the accepted r1 route.
Native proving is untouched: the native profile stays `conjectured128_b2_q108_p20_fold4`,
so native AOT catalogues, native fixed authorities and native proofs stay valid.

## What changes

| | r1 (accepted, default) | m3 (this version) |
|---|---|---|
| Outer profile | `r1_b2_q108_p20_fold4` | `m3_b4_q51_p26_fold4` (alt. `m3_b8_q34_p26_fold4`) |
| Outer log_blowup / queries / PoW | 1 / 108 / 20 | 2 / 51 / 26 (alt. 3 / 34 / 26) |
| Fold step / last layer | 4 / log 0 | same |
| Outer domain string | `stwo/circuit/native-om31/q108-p20-fold4/lens-v1` | `stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1` |
| Fold arity | 2 (streaming binary carry) | 4 (streaming 4-ary carry) |
| Fold message version word | 1 | `(arity << 8) | 2` for arity ≠ 2; 1 for binary |
| tree.json | schema 2 (`left`/`right`) | schema 3 (`children`, `fold_arity`, `outer_profile`) |
| 17-leaf block (24628607) | 16 folds, depth 5 | 6 folds, depth 3 |

What the profile applies to: every *outer* proof, meaning the leaf wrappers' own proofs
and every fold. Leaf circuits still verify *native* proofs at q108, so leaf verifier
circuits do not shrink. Fold circuits verify outer proofs and shrink with the outer
query count.

## Selection and binding

- **Selection is process policy.** `STWO_RV64_OUTER_PROFILE` takes `r1`, `m3`, or a full
  profile name. `STWO_RV64_FOLD_ARITY` takes a value in 2..4 and defaults to 2 under r1
  and 4 under m3. The producer and the receiver must both select the same values. Proof
  bytes never select a profile. An unknown name panics, so selection fails closed.
  `protocol.select()` refuses to change a profile once it has been used.
- **Exact parameters.** `Profile.config()` is the only source of the outer config.
  `validateConfig` requires exact equality with the active profile, so a proof with
  another query, PoW, blowup, or fold value is rejected
  (`UnsupportedOm31CircuitProfile`, `InvalidOm31CircuitProof`).
- **Domain separation.** The profile's domain string is hashed into four places:
  1. every outer authority identity (`prove.zig` `Authority.initImpl`);
  2. the wire header (`wire.zig` `profile()`), so an r1 receiver rejects an m3 wire
     with `Om31CircuitWireProfile`;
  3. the outer transcript (`mixProfile`), after `PcsConfig.mixInto`;
  4. the in-circuit verifier transcript (`om31_outer.zig` `Statement.mixPublic`).
  The FIXED commitment is sealed at the profile's blowup, so FIXED roots differ too.
- **Arity binding.** The fold digest message carries the arity in its version word for
  any arity ≠ 2, and the receiver recomputes every digest from the plan it derives
  itself (`Plan.initArity`). The tree shape cannot come from the producer: the receiver
  preflights exactly the files of its own plan and requires every node to be restored.

## Soundness accounting (conjectured, same assumption as native)

This uses the same model as `rv64-gkr-conjectured128-profile.md`: the ethSTARK
conjecture (list decoding up to capacity for the circle code), with each query passing
with probability ≤ ρ, plus ideal-hash Fiat–Shamir.

**1. FRI queries + PoW per outer proof.** At rate ρ = 1/4 (log_blowup 2), each query
contributes 2 conjectured bits:
`2·51 + 26 = 128`. The PoW is checked after the last FRI commitment and before query
derivation (`core/pcs/verifier_family.zig`), as in native, so the 26 bits count toward
the query phase. The alternative profile gives `3·34 + 26 = 128`. Every attempt targets
a single outer transcript, so the per-attempt bound is 2^-128 and does not grow with
the number of nodes. The adaptive multi-scope argument is unchanged; only H, the
number of hashed scopes, changes:
- r1 (16 folds): H = 3·(17+16+1)+1 = 103.
- m3 (6 folds): H = 3·(17+6+1)+1 = 73.

H enters only the 2^-256-scaled collision term. Fewer nodes means *less* loss.

**2. Algebraic terms in the outer field (OM31, 2^248, μ = 2^-243.3).** Raising the
outer blowup from 2 to 4 doubles the DEEP/FRI evaluation domain (2N → 4N). Each term
whose weight is proportional to that domain therefore loses exactly 1 bit (2 bits at
b8). The OODS term is taken over a fixed multiple of N and does not change. [D] The
outer weights themselves (outer trace sizes, about 90 columns, ≤ 16 composition
columns, the circuit AIR's constraint count) have not been rerun through
`model.py` for outer proofs. That is an open item. [E] By analogy with the native
table (197–209 bits at weights up to 10^14), the outer union is expected to stay
above about 2^-190, far below the 2^-128 query term. Under the conjecture, the
composition and LogUp claims of the circuit AIR do not depend on the rate.

**3. Fold arity.** A 4-ary fold verifies four complete outer proofs in one circuit,
using the same verifier code as the binary fold: each child gets its own guessed proof,
its own `V.verify`, and its own FIXED-root equality against the child authority. Each
child's verification is a separate sub-statement with its own transcript, so the
fold's soundness error is the union of its children's errors plus its own. That is the
same accounting as two levels of binary folds. Over the whole tree the union runs over
24 child verifications (r1: 32), and the per-attempt bound stays at 2^-128 for the
attempt that targets one proof.

**4. Leaf → outer composition.** Leaves verify native proofs under the native profile,
which is unchanged. The leaf wrapper's own proof is an outer proof under m3. The fold
at the next level verifies that proof under m3. Native and outer bounds are separate,
per-attempt 2^-128 terms, as in r1.

**Conclusion.** m3 matches r1's per-attempt conjectured security, 128 bits under the
same ethSTARK assumption and ideal hashes, and has a slightly smaller collision-term
multiplier. It is not a proven bound, no certificate exists, and `security_qualified`
stays false.

## CPU outer prover at blowup > 2

The CPU circuit component read the committed LDE directly at the 2n evaluation domain. That is valid only at
blowup 2, and it is why m3 first failed with `InvalidLogSize`. When an LDE is taller than 2x its polynomial,
`component.zig` now evaluates each column it reads from that column's coefficients on its own 2x canonic
domain, then applies the same lifted read as before. This is exactly what the beta1 route reads. At r1 no
column triggers this path (`needsShadow` is false), so r1 proofs are unchanged. The GPU composition already
re-evaluates trace polynomials from coefficients on the evaluation domain.

## Measured effect

See `vectors/reports/rv64-m3-20261104/recsize/README.md`. Per verified child, an m3 fold is 0.50x r1 in
variables, tasks and Blake gates. Over the 17-leaf tree, fold variables total 0.34x (6 folds, depth 3,
instead of 16 folds, depth 5). Leaf circuits are unchanged.

## What is not covered / open

- **GPU outer prover at blowup 4 is not qualified.** The CPU outer prover and verifier
  are generic and tested here. The GPU trace commit, FRI plan, PCS request, and grind
  all take their blowup from the config. The resident composition commit had beta 1
  hard-wired as a context default; it now takes the outer profile's beta per call
  (`evaluateRolesAtBlowup`). The non-`separate` n2b path (beta ≥ 2) has no GPU receipt
  yet, and device memory at b4 is untested. A b4 LDE doubles the committed-LDE bytes of
  every outer proof.
- **Fused Blake2s compression gadget** (review-plan M3): not done in this stream. It is
  a new circuit AIR component with new GPU composition/assignment kernels, and it is the
  remaining lever for *leaf* circuits (Blake ≈ 74% of leaf variables). See the receipt
  for the measured fold/leaf split it would act on.
