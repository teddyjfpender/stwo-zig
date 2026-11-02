# Composed native OM31 security: finite conditional analysis

This analysis covers the actual complete Ethereum bundle at block 24,628,607: 25CPU proofs and 5truth proofs, 104,253,913 retirements. The candidate is native OM31/raw-Blake, β2, 256queries, PoW 0 and fold 4. It is **not a new certificate**. A finite conditional budget is now calculated, rather than replacing the missing proof by an uninstantiated factor. Remaining theorem-to-implementation obligations and the weaker/unintegrated recursive layer are explicit. No protocol, parameter, receiver or benchmark default changes here.

Source revision is `8ce5fb0a7d104baadf812c55fa3985a2406274d2`. The report directory `vectors/reports/rv64-composed-security-20261102/` pins source-file hashes, bundle/fresh-receiver hashes, exact integer formulas and an executable Fraction-based calculation. The source_shape in the independent fresh receiver has 30proofs, maximum trace log 22, 7,371columns, 6,128constraints, 5 samples/column, degree 5, 22 local instances and 26 GKR variables. These are analysis inputs derived by the receiver, not an authority accepted from producer Facts.

## Primary theorem anchors and a useful conservative regime

Primary sources consulted are the [S-two whitepaper 2026/532](https://eprint.iacr.org/2026/532), its [author-uploaded full text](https://www.researchgate.net/publication/407022099_S-two_Whitepaper), and [Papini–Haböck LogUp-GKR 2023/1284](https://eprint.iacr.org/2023/1284) ([author full text](https://www.researchgate.net/publication/373444175_Improving_logarithmic_derivative_lookups_using_GKR)). The whitepaper's Theorem 6 gives the adaptive-RO formula `(T+R)*max(e_i)+3*(T²+1)/2^λ`. Its unique-decoding remarks and §4.5 cover the current non-squaring-consistent query layout in that regime; the list-decoding correspondence remains open there. §4.4 gives the quotient-only enlarged-space correction. LogUp-GKR §3.2 gives the cubic-sumcheck/GKR degree accounting, while noting its analysis is informal.

For β2, rateρ=1/4. With minimum nonzero table size 32, quotient-only correction gives `rho_plus=(1/4)*(1+2/32)=17/64`. Choose the **analysis** agreement `alpha=41/64`, distance `theta=23/64`. Then `theta<(1-rho_plus)/2`; this is strictly inside unique decoding even for the enlarged space. The earlier 5/8 agreement is on the original unique-radius boundary and should not be silently called a proven strict regime. No protocol parameter changes are needed to analyze a weaker agreement. All 256 raw query positions still count: duplicates are sampled IID before deduplication, and checking an entire fold 4block is no weaker than checking its selected position.

The corresponding whole-roster query term is exactly `30*(41/64)^256`, about **2^-159.56**. Thus there is room to choose a conservative proof regime rather than relying on the unproved list-decoding-layout claim. The OM31 quadratic-conjugate quotient and fold 4 insertion/folding correspondence still require a written implementation-to-theorem review; this document does not substitute a numeric margin for that work.

## Actual randomness and algebraic events

Let `mu=3^8/2^256=6561/2^256`. Each raw32-bit word reduced modulo `p=2^31-1` has at most three preimages. An OM31 challenge consists of eight independently uniform raw words from one ideal raw-Blake block. Any set of at mostDbad field points therefore has probability at most `D*mu`. For several independently drawn coefficient coordinates, multivariate root counting gives the total-degree version of the same bound. This accounts for the actual biased sampler; replacing it by uniform1/p^8 without justification is unnecessary.

The following weights are over the entire native roster; multiplying each bymu gives the displayed conditional error.

| Event | Total degree/support weight | Conditional bits |
|---|---:|---:|
| Joint cleared lookup identities, all local/global scopes |3,804,538,944|211.50|
| GKR cubic sumchecks |536,250|224.29|
| GKR instance/layer mixing |15,600|229.39|
| Late terminal N/D eta binding |550|234.22|
| Secp modular-product compression |24,506,368|218.77|
| Composition coefficient mixing |183,840|225.83|
| Coarse OODS correspondence |148,397,830,963,200|196.24|
| DEEP sample batching |1,105,650|223.24|
| Conservative unique-curve FRI correspondence |949,874,967,183,360|193.57|

The last three rows depend on the stated PCS/FRI correspondence review. They are not presented as already machine-checked or externally reviewed proofs. Their formulas are concrete: OODS uses `32*P*C*S*N`, overcounting mask poles and a common-denominator residual of degree bounded by component count and `d*N`; DEEP uses `P*C*S`; FRI uses `P*8*32*(C+1)*(4N)`. Four binary folds contribute challenge degree 15. At most C insertions can add at most 30C through the squared challenge powers, giving the conservative `32(C+1)` curve degree. The unique-curve bad-set threshold is degree times domain size, and 8 macro-rounds overbounds the admitted heights. Review must establish that these exact source expressions match the theorem's enlarged-space and multi-domain relation, including every conjugate/offset. These are not the old unexplained65,536factor or a claim that passing unit tests proves proximity soundness.

Secp's source polynomial has degree 62: two 32-byte polynomials multiply, while the carry polynomial has 62 coefficients and is multiplied by a degree-one factor. The source consumes an independent OM31 challenge after sealed MAIN. The conservative row union uses 395,264 product rows, including padding. Its byte/carry bounds must justify that a false integer modular identity is not already zero coefficientwise moduloM31.

### Why the quadratic tuple-pair union is avoidable

Fix all sealed MAIN tuples and weights before drawing relation offsets and independently drawn coefficient vectors. For a distinct tuple support element write `D_i=z_r-<a_r,t_i>`, with separate variables for each namespace. Aggregate identical tuples first. If a relation is false and some aggregate residue w_i is nonzero modulo p, the cleared numerator

`H = sum_i w_i * product_{j != i} D_j`

is a nonzero multivariate polynomial: restrict to `D_i=0`, leaving a nonzero weight times a product of differences of distinct formal linear forms. Different namespaces have different z variables. Hence total degree is at most support minus one, without separately paying an all-pairs tuple-collision term. The source draws independent coefficient vectors for CPU relations, RAM, KIO and Wire; scalar BYTE coefficients fixed to 1 are also injective in their scalar input. A powers-of-one-challenge compression would instead need its actual larger degree.

This requires the source unit/valid-provider-support and characteristic lemmas: a false semantic relation must yield a nonzero residue, not a multiple ofp. Weighted multiplicities are not automatically ordinary signed masses. REG/OWNER use unit consistency; membership relations use unit consumers and constrained valid provider support. The receiver's current source-bound path checks the ordinary counts it derives; its source canonicality and weighting interpretation still needs review as part of the whole construction. Physical denominator slots safely overbound support, including repeated/zero-weight/padded slots. The old all-pairs lookup budget is about 183 bits; the joint argument raises this to211.5bits. Queries dominate either way.

### Binding and rejection events

Nondegenerate row challenges determine the two anchored Eq recurrence cycles uniquely. The cyclic prefix enforces `sum Eq(row)*(N+etaD)=claimedN+eta*claimedD` because the row count is nonzero modulo p. `eta` is drawn after both terminal marginals are fixed. A wrong pair survives with at mostmu per instance, unioned over instances. The MAIN projection must use the same full-row tuple expression, not a product of independently interpolated MLEs; the current authority does so. Its degree stays at most three after multiplication by Eq.

Lookup poles, row coordinates 0/1, stereographic poles and degenerate quadratic-conjugate lines are rejected by the current verifier/prover authorities. They are completeness/abort events, not automatically false-acceptance terms. In particular, a seed or folded point entering the OM31 inner subfield can have probability much larger than mu, but the explicit degenerate-line rejection prevents turning that into an acceptance error. No retries, denominator masking or security credit for the candidate's zero-bit PoW is assumed.

## Adaptive Fiat–Shamir and the whole native bundle

The source-count round envelope used by the executable calculation is

`25*(2V²+(4I+16)V+128)+30*(2CS+512+16V)+4096 = 2,347,836 < R=2^22`.

It deliberately treats many values as separate messages. GKR layer/round counts and native sampled-column counts are geometry-bound. This is an **analysis** bound; an independently checked transcript-round authority and a multi-scope BCS correspondence remain required. Shared RAM/KIO/Wire challenges follow the ordered manifest of every sealed MAIN/root/local marginal, and local scopes bind statement/ordinal/geometry. Parallel execution is not permission to ignore adaptive grinding over those scopes.

A conservative composition unions 30 native proofs plus the shared challenge protocol. Retaining each proof's BCS hash term and one additional identity-hash collision term gives

`eps_native(T) <= (T+2^22)*E + 94*(T²+1)/2^256`,

where `E=sum(degree_weights)*mu +30*(41/64)^256`.

This is a finite **conditional** bound, not an implemented certificate. It assumes the stated source nonzero-polynomial, sampler, unique-decoding PCS/FRI and multi-scope ROM correspondences. Domain-separated raw-Blake and SHA identity hashing are modeled as appropriate ideal hash authorities; actual cryptanalytic assumptions are separate.

| Adversarial RO budgetT | Bound on success/query, bits |
|---|---:|
|1|137.56|
|2^64|159.56|
|2^120|129.45|
|2^121|128.45|
|2^122|127.45|

Bounding the decreasing `(1+R/T)*E` and increasing hash term separately gives more than 129 bits per query uniformly for `1<=T<=2^120`. This matches a bounded-work candidate model and is not a 2^-128 statistical failure claim for a 2^120 query adversary. At 2^120 the conservative total success bound is about 0.00143.

Raw 256-bit hashing does **not** make the whitepaper's exact constants prove an unrestricted literal128-bit per-work inequality near 2^128 queries. The table's bound becomes uninformative there; this is a proof-bound limitation, not a demonstrated attack. A global single-collision-event analysis may remove the conservative per-proof factor, but even coefficient 3 has a constant-factor distinction from an exact128-bit target. Decide the concrete work definition and tolerated constants. If a strict unrestricted inequality is required, a wider commitment/FS digest (or a different reviewed reduction) must be costed; increasing FRI queries or OM31 width cannot repair that hash term. No hash migration is proposed without review.

## What remains before a claim, and recursion

For the native bundle, the practical next step is to review the unique-decoding implementation correspondence, formalize the source weighting/canonicality and late-binding lemmas, verify the transcript-round/multi-scope ROM reduction, and register the resulting receiver-owned statement of assumptions and work range. More queries are not the first missing ingredient. This analysis deliberately keeps the receiver's `security_qualified=false` and certificate registry unchanged.

A composed recursive result additionally obeys `eps_total <= eps_native + sum eps_leaf/fold/root + statement/topology binding errors`. The existing RV64 recursion substrate proves outer circuit AIRs with QM31-based profiles; its internal FS channel is M31-reduced, although its Merkle commitments are plain unreduced 256-bit Blake. Numerical OM31 circuit-verifier tests do not upgrade those outer proof-system challenges or establish an accepting full recursive receiver for this new global-GKR execution lane. Therefore no finite128-bit **recursive whole-protocol** claim follows from this native budget. Each outer layer needs a matching reviewed secure-field/channel/parameter identity and a counted topology/error budget, plus actual end-to-end statement/coverage/global-debt closure.
