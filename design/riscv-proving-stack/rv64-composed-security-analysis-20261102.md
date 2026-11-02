# Composed native OM31 security: finite conditional analysis

This analysis covers the actual complete Ethereum bundle at block 24,628,607: 25CPU proofs and 5truth proofs, 104,253,913 retirements. The candidate is native OM31/raw-Blake, β2, 256queries, PoW 0 and fold 4. It is **not a new certificate**. A finite conditional budget is now calculated, rather than replacing the missing proof by an uninstantiated factor. Remaining theorem-to-implementation obligations and the weaker/unintegrated recursive layer are explicit. No protocol, parameter, receiver or benchmark default changes here. The intended-execution AIR semantics and source canonicality premises are separate from the probabilistic soundness calculation.

Source revision is `8ce5fb0a7d104baadf812c55fa3985a2406274d2`. The report directory `vectors/reports/rv64-composed-security-20261102/` pins source-file hashes, bundle/fresh-receiver hashes, exact integer formulas and an executable Fraction-based calculation. The source_shape in the independent fresh receiver has 30proofs, maximum trace log 22, 7,371columns, 6,128constraints, 5 samples/column, degree 5, 22 local instances and 26 GKR variables. These are analysis inputs derived by the receiver, not an authority accepted from producer Facts.

## Security qualification and handoff

**The PR implements and functionally qualifies the wider native candidate; it does not complete promotion from nominal96 to certified whole-protocol128.** Complete-block proof acceptance, exact-artifact checks and a finite security analysis are distinct evidence. Neither acceptance nor the model's conditional bound changes the fail-closed certificate policy.

| Lane / authority | Parameters and evidence | Security classification / handoff gate |
|---|---|---|
| Existing QM31 benchmark control (`native_q70_p26_qm31_control_v1`) | QM31,70queries,26query-PoW bits; legacy control remains unchanged | Nominal96-bit PCS benchmark accounting only. It does not establish96-bit soundness for every algebraic, execution and recursive obligation; it certainly is not128. |
| Native OM31 engineering control (`experimental-om31-local-gkr-q70-p26-fold4`) | OM31,raw-mod Blake,β1,70queries,P26,fold4; actual services proofs and fresh receivers | Functional control for field/GKR engineering. No reviewed whole-protocol security certificate. |
| Native OM31 candidate (`experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering`) | OM31,raw-mod Blake,β2,256queries,P0,fold4; independently sourced β2 fixed keys; complete104,253,913-step block/30proofs accepted by a fresh receiver | Target128, explicitly experimental. Source-correspondence proof outline is reviewed for coherence; independent theorem/semantic/ROM review remains. Conditional model bounds success per RO query below2^-128.596 for this actual roster and total work1..2^120 under its assumptions. This is not an unconditional failure probability nor unrestricted128 certification. |
| Recursive aggregate for the new OM31/global-GKR execution | Numerical OM31 verifier/circuit foundations exist; current outer recursion proof field/profile is still separate and weaker | No qualified end-to-end128 recursive construction. Count and qualify every outer leaf/fold/root error and statement/global-debt closure before any composed claim. |

The native candidate's remaining promotion gates are: (1) independently approve the source weighting/canonicality, characteristic and nonzero-residual premises, together with the documented unique-FRI/DEEP/OODS correspondence; (2) instantiate and review the adaptive Fiat–Shamir/BCS reduction across local-GKR, native-PCS and shared-manifest scopes; (3) select a concrete work/security definition and address the exact raw256-bit hash-reduction constants outside the bounded1..2^120 analysis; (4) validate an execution-specific budget at receiver-owned caps rather than reuse this30-proof calculation for arbitrary256-proof inventories. The recursive outer construction is an additional gate, not hidden inside these native results.

Guest optimization and GPU work can proceed using these explicit identities. Preserve field width, raw sampler/transcript order, fixed-key rate/geometry authority, authenticated global obligations and canonical proof encoding. Exact output/artifact and fresh-receiver checks remain functional gates; performance receipts must continue reporting `security_qualified=false`. A guest/geometry change requires regenerating the source-derived roster/mass analysis. GPU acceleration supplies no security credit and must not silently select a different query count, digest, field or profile.

## Primary theorem anchors and a useful conservative regime

Primary sources consulted are the [S-two whitepaper 2026/532](https://eprint.iacr.org/2026/532), its [author-uploaded full text](https://www.researchgate.net/publication/407022099_S-two_Whitepaper), and [Papini–Haböck LogUp-GKR 2023/1284](https://eprint.iacr.org/2023/1284) ([author full text](https://www.researchgate.net/publication/373444175_Improving_logarithmic_derivative_lookups_using_GKR)). The whitepaper's Theorem 6 gives the adaptive-RO formula `(T+R)*max(e_i)+3*(T²+1)/2^λ`. Its unique-decoding remarks and §4.5 cover the current non-squaring-consistent query layout in that regime; the list-decoding correspondence remains open there. §4.4 gives the quotient-only enlarged-space correction. The accessible September2023 author revision of LogUp-GKR §3.2 gives cubic-sumcheck/GKR degree accounting, while noting its analysis is informal. IACR metadata lists a later2025 revision; its PDF was inaccessible through these tools. The degree budget here is independently reconstructed from source, not claimed as a review of that inaccessible revision. Access/version details are recorded in primary-sources.json.

For β2, rateρ=1/4. With minimum nonzero table size 32, quotient-only correction gives `rho_plus=(1/4)*(1+2/32)=17/64`. Choose the **analysis** agreement `alpha=41/64`, distance `theta=23/64`. Then `theta<(1-rho_plus)/2`; this is strictly inside unique decoding even for the enlarged space. The earlier 5/8 agreement is on the original unique-radius boundary and should not be silently called a proven strict regime. No protocol parameter changes are needed to analyze a weaker agreement. All 256 raw query positions still count: duplicates are sampled IID before deduplication, and checking an entire fold 4block is no weaker than checking its selected position.

The corresponding whole-roster query term is exactly `30*(41/64)^256`, about **2^-159.56**. Thus there is room to choose a conservative proof regime rather than relying on the unproved list-decoding-layout claim. The OM31 quadratic-conjugate quotient and fold 4 folding correspondence still require a written implementation-to-theorem review; this document does not substitute a numeric margin for that work.

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
| DEEP sample batching, common-domain CA |18,549,728,870,400|199.24|
| Unique-curve FRI, source-specific single first layer |60,397,977,600|207.51|

The PCS rows still need an independent OODS/DEEP correspondence review. OODS uses `32*P*C*S*N`, overcounting mask poles and a common-denominator residual; DEEP uses `P*C*S*4N`. The corrected FRI bound is `P*8*15*(4N)`: this implementation has one first-layer polynomial, not per-height insertions during FRI. Appendix below instantiates the actual degree-15 unique-decoding theorem and the sibling reconstruction, rather than assuming that a linear-FRI theorem extends automatically.

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

The round count now follows **all accepted candidate caps**, not only the measured roster. With `I<=128`, `V<=30`, tuple arity `A<=128` and proof count `P<=256`, a local child has at most

`V*(2I+3)+V*(V-1)+4I+1+9*(A+2)+32 = 10,355`

challenge/message operations. Per layer this counts active-claim mixes, two initial draws, polynomial mix plus challenge per sumcheck round, returned-mask mixes and final challenge. The begin/scope/instance encoding and nine relation namespaces are included. The native PCS path is bounded by 256 operations per proof: at most eight macro-FRI rounds, root/sample/terminal mixes, fixed OODS/composition/DEEP draws and 32 raw query draw blocks; value-vector widths are not additional rounds. Shared manifest draws/mixes add at most 256. Thus `256*(10,355+256)+256 = 2,716,672 < R=2^22`. Source authorities are `om31_security_candidate.zig` caps, `child.begin`, `challenges.draw`, `verifier_kernel.zig`, `core/fri_family.zig`, `core/queries.zig` and `manifest.drawShared`. No new runtime transcript-counter authority or protocol is introduced.

A deliberately conservative composition counts the 25 local-GKR subprotocols separately from 30 native PCS proofs and one shared-manifest protocol. Keeping each scope's BCS hash term, plus an identity-hash term, gives

`eps_native(T) <= (T+2^22)*E + 169*(T²+1)/2^256`,

where `E=sum(degree_weights)*mu +30*(41/64)^256`.

This is a finite **conditional** bound, not an implemented certificate. It assumes the stated source nonzero-polynomial, sampler, unique-decoding PCS/FRI and multi-scope ROM correspondences. Domain-separated raw-Blake and SHA identity hashing are modeled as appropriate ideal hash authorities; actual cryptanalytic assumptions are separate.

| Adversarial RO budgetT | Bound on success/query, bits |
|---|---:|
|1|137.56|
|2^64|159.56|
|2^120|128.60|
|2^121|127.60|
|2^122|126.60|

Bounding the decreasing `(1+R/T)*E` and increasing hash term separately gives more than 128.59 bits per query uniformly for `1<=T<=2^120`. This matches a bounded-work candidate model and is not a 2^-128 statistical failure claim for a 2^120 query adversary. At 2^120 the conservative total success bound is about 0.00258.

Raw 256-bit hashing does **not** make the whitepaper's exact constants prove an unrestricted literal128-bit per-work inequality near 2^128 queries. The table's bound becomes uninformative there; this is a proof-bound limitation, not a demonstrated attack. A global single-collision-event analysis may remove the conservative per-proof factor, but even coefficient 3 has a constant-factor distinction from an exact128-bit target. Decide the concrete work definition and tolerated constants. If a strict unrestricted inequality is required, a wider commitment/FS digest (or a different reviewed reduction) must be costed; increasing FRI queries or OM31 width cannot repair that hash term. No hash migration is proposed without review.

## What remains before a claim, and recursion

For the native bundle, the practical next step is to review the unique-decoding implementation correspondence, formalize the source weighting/canonicality and late-binding lemmas, verify the transcript-round/multi-scope ROM reduction, and register the resulting receiver-owned statement of assumptions and work range. More queries are not the first missing ingredient. This analysis deliberately keeps the receiver's `security_qualified=false` and certificate registry unchanged.

A composed recursive result additionally obeys `eps_total <= eps_native + sum eps_leaf/fold/root + statement/topology binding errors`. The existing RV64 recursion substrate proves outer circuit AIRs with QM31-based profiles; its internal FS channel is M31-reduced, although its Merkle commitments are plain unreduced 256-bit Blake. Numerical OM31 circuit-verifier tests do not upgrade those outer proof-system challenges or establish an accepting full recursive receiver for this new global-GKR execution lane. Therefore no finite128-bit **recursive whole-protocol** claim follows from this native budget. Each outer layer needs a matching reviewed secure-field/channel/parameter identity and a counted topology/error budget, plus actual end-to-end statement/coverage/global-debt closure.


## Source-specific fold-4 correspondence

The primary [S-two whitepaper](https://eprint.iacr.org/2026/532), Appendix A.2 **Remark 12**, explicitly states degree-M curve decodability in the strict unique regime with threshold `M*|D|`. **Remark 13** explicitly extends both CA over given sets (Theorem 8) and weighted CA (Theorem 9) to the same threshold. This is stronger than interpolating M+1 separately close codewords and taking a union of disagreements.

Instantiate a macro fold of size `m=2^s<=16`. Iterated even/odd decomposition writes each input fiber as coefficient functions `f_0,...,f_(m-1)` on the quotient domain. Source challenges `z,z²,z⁴,z⁸` combine these as `sum z^j*f_j`, degree at most 15 in z. The inverse-butterfly matrices are invertible because the characteristic is odd and the canonical-domain twiddles are nonzero. Low-degree coefficient codewords reconstruct one original low-degree word. All coefficient functions jointly agreeing on a quotient-domain set A means agreement at **all m siblings** above A; its density is still |A|/|D|, not divided by m.

To see why the same agreement density survives, use Remark 12 to obtain a degree-M curve of proximates. At any coordinate where the coefficient vector differs, accidental agreement is a nonzero degree-M polynomial in z. Across the domain there are at most M|D| bad z. Beyond that threshold one proximate agreement set has no accidental coordinates; Theorem 8/Remark 13 then gives joint coefficient agreement on that same set. The weighted version transports the conditional success weights from previously committed layers. Hence the standard backward query-success argument applies with unchanged theta. Full sibling openings are checked by `core/fri_family.zig.verify` through `foldCircleSubsets`/inner `verifyAndFoldImpl`; this is not a test of just one arbitrarily chosen linear combination.

The important source restriction is verified in `prover/fri_commit_ops_family.zig.commitInnerLayers`: it accepts exactly one `FirstLayerProver`, folds it circle-to-line, then folds only that line evaluation. It has **no smaller-height source insertion inside a macro round**. `pcs/quotient_field.zig.computeChunk` has already produced one common-domain quotient word before `fri_lazy_commit_family.zig` passes it to FRI. The earlier `32(C+1)` insertion-degree discussion was therefore inappropriate for this source and has been removed. Multi-height column soundness belongs to the preceding PCS/DEEP lifting correspondence; it is not secretly discharged by this FRI argument.

At most eight macro rounds, challenge degree at most15, and domain size at most4N give the conservative threshold `8*15*4N` per native proof. Nonuniform raw-mod sampling changes bad-set probability to threshold*mu. This closes the specific generic-curve/arity-16 gap, subject to independent review of the stated circle/line coefficient-space correspondence. It does not certify the remaining OODS/DEEP or execution-semantic premises.

A fold-1 engineering alternative already exists in the source. It uses fresh independent challenges after each binary commitment, up to24 instead of6 macro rounds at the maximum domain. It removes the arity-16 correspondence obligation but introduces roughly four times as many FRI root commitments/draws and more authentication paths; exact proving/recursion cost needs measurement under a distinct receiver-owned profile. It is not selected here.

## Possible tighter multi-scope hash accounting — not used numerically

All local children begin with the GKR tag, statement/fixed/MAIN roots, ordinal and ordered instances. Native workers have a different tag, kind/ordinal and statement; shared challenges have the manifest tag and digest. No challenge is drawn before these scope bindings. Raw draw inputs have length37 while transcript mix inputs have length divisible by4, and raw query counters cannot wrap under the round cap. Conditional on no state/hash collision, distinct post-scope challenge queries therefore belong to disjoint challenge streams. Repeated public configuration prefixes have no secret challenge at that point.

This supports investigating `sum T_i<=T`, `sum T_i²<=T²`, and replacing per-scope quadratic terms by a single global collision event plus scope constants. However the commitment hashing, identity hashing, repeated fixed trees, and the BCS binding-oracle reduction must be audited together; domain tags alone are not a proof of a universal multiscope ROM theorem. The executable model deliberately retains coefficient169, rather than claiming the potentially much tighter coefficient4. Both versions still have a constant-factor distinction from unrestricted literal128 near T=2^128.


## OM31 two-point DEEP and lifting correspondence

Let `p=2^31−1`, `K=OM31=F_(p^8)`, `H=QM31=F_(p^4)`, and write K=H[v]/(v²−u). The involution σ(a+bv)=a−bv is Frobenius p^4, not the older QM31 p² involution. The field construction's nonsquare proof and native `OM31.quadraticConjugate` fix this authority. Since every physically committed coordinate polynomial has M31 coefficients, `f(σz)=σ(f(z))`. An OM-valued trace/composition is opened as eight separate M31 coordinate polynomials; the argument is applied coordinate-wise before reconstructing the secure value.

For z=(x0+v*x1,y0+v*y1), claimed value w and an M31 domain point P, define the affine interpolation

`R(P)=w+(σw−w)*(P.y−z.y)/(σz.y−z.y)`.

Then R(z)=w and R(σz)=σw. Source `constraints.quadraticConjugateLineCoeffs` gives exactly the numerator coefficients of this expression, multiplied by the batching power. `quadraticLineDenominator` gives the H-valued line

`D(P)=(x0−P.x)*y1−(y0−P.y)*x1`.

The geometric pair vanishing polynomial is `−2v*D(P)`. Thus the production quotient is a nonzero scalar multiple of `(f(P)−R(P))/pairVanishing(z,σz;P)`, which is the two-point quotient discussed in whitepaper §4.5. The denominator is σ-fixed; no QM31 approximation/reinterpretation occurs. Rejecting `z.y=σz.y` makes interpolation well-defined; zero row denominators are rejected even at zero numerator. Degenerate sampling is an abort/completeness event, never silently resampled or converted to acceptance.

The paper states the conjugate construction for F_(p^4)/F_(p^2), while its argument uses only a quadratic extension, fixed-field coefficients and two distinct conjugate points. Replacing that tower by K/H therefore preserves the algebraic proof: M31 remains inside H; any M31 polynomial commutes with σ. This is an explicit extension-field instantiation, not a claim that the paper directly names OM31.

### Common-domain lifting and extraction

For a column of native size Ni and largest trace size N, source sampling evaluates `f(π^(logN−logNi)(z))`. All mask points remain global. A base-field circle translation commutes with the doubling pullback, so previous/next/±2 masks evaluate the corresponding translated local polynomial. The physical queried index `((position >> (difference+1)) << 1)+(position & 1)` is precisely this pullback, including the conjugate branch. `geometry.zig` checks the same point/denominator relation over unequal domains. A column is not sampled as an unrelated full-height witness.

DEEP's batching powers form a degree-(Kqueries−1) curve of the individual quotient words. Apply unique correlated agreement to that curve over the **single common domain**, with the quotient low-degree space as the constrained code. The bad-coefficient threshold is at most `Kqueries*|D|`, rather than Kqueries alone. The model therefore corrects `deep_batching` to `P*C*S*4N`. This is separate from the subsequent degree15 FRI fold argument.

For a decoded quotient q, form `F=R+pairVanishing*q` (up to the fixed nonzero scalar). Multiplication by the affine circle line enlarges the circle degree by at most1, hence root-count dimension by at most2. The original committed coordinate word is M31-valued. F and every coefficientwise Frobenius image agree with that same word; strict unique decoding forces them equal. This descends F's coefficients to M31. Likewise the lifted word is invariant under every kernel translation of the pullback π^difference. F and its translate agree on an intersection of density at least `2*alpha−1`. Here `2*(41/64)−1=18/64 >17/64`, exceeding the enlarged polynomial's root-density bound. Consequently F is kernel-invariant. In the split-circle Laurent coordinate, invariance under the kernel forces exponents divisible by its order, so F descends to the native small-domain polynomial. This also explains why singleton-mask columns do not rely on the optional extra periodicity sample alone.

The FRI **first-word** code still has rate1/4. The conservative `rho_plus=17/64` instead bounds the enlarged ORIGINAL-coordinate extraction space: `(Ni+2)/(4Ni)<=17/64` for every nonzero Ni>=32. It is not a claim that the committed FRI first word has rate17/64. Choosing alpha41/64 puts both spaces strictly inside the unique regime. No conditional list-size or non-squaring-compatible list-decoding layout conjecture is used here.

### Explicit OODS degree envelope

An independently reviewed correspondence must include the public anchor/carry computations in `logup_gkr/mle_point.zig`, not just the catalog's AIR degree. Their apparent divisions can be eliminated algebraically. For `y_a=y(π^a P)`, the circle law gives `y_(a+1)=2*x(π^a P)*y_a`. Therefore every `v0/vj` in `evalStepSelectorFor` is a polynomial product of doubled x coordinates. Its squared `v0/v1` term and every other term have circle degree at most Ni/2. For `evalIsFirstFor`, translating the first trace point to the unit turns the coset vanishing into a nonzero constant times `y(P)*product x(π^i P)`; the division by pointVanishing cancels y and leaves the degree-Ni/2 Lagrange polynomial. Off-domain poles in the implementation are rejected. The weighted sum forming carry and both anchors retain this degree. Their coefficients depend only on the earlier GKR challenges, fixed before the OODS draw.

After pullback, every coordinate proximate or public anchor/carry has degree at most `N/2+1` (the +1 conservatively covers quotient-only extraction). Every translated mask preserves this bound. Actual CPU/global/Keccak/secp constraint products have degree at most5, so their numerator degree is at most `5*(N/2+1)<3N` for N>=32. A composition reconstructed from split1 or split2 coordinate pieces has degree at most2N; allowing4N is conservative. Each component's vanishing denominator has degree N/2 after pullback. There are at most C components because every admitted component contributes at least one counted column. Clearing their product gives a residual with circle degree at most `(C/2+4)*N`. Substituting the stereographic seed (rational coordinates with numerator/denominator degree2) produces a univariate numerator of degree at most `(C+8)*N`. For every C>=1,S>=1,

`(C+8)*N <=32*C*S*N`.

This gives the specific constant32 used by the executable OODS envelope; it is not an empirical safety multiplier. All source mask offsets, secure-coordinate counts, and both production composition splits are covered. The nonzero-residual premise follows the composition-randomness reduction plus identification of the selector expressions with the intended interpolants and the authenticated source AIR. Failure of an execution-semantic/source canonicality premise is not cured by this root count. Source OODS checks compare the independently reconstructed composition with the same constraint authority before PCS verification.

### Scope of the numerical result

The finite degree/query/collision sums in model.json concern the **actual30-proof block**, with its source-derived masses and roster. Only the transcript-round bound is proved using ALL accepted caps256proofs/128instances/30variables. A256-proof accepted-shape envelope would need its own lookup masses, degree sum and scope count; substituting the30-proof numbers is invalid. In particular the fully conservative per-scope hash coefficient at256CPU proofs would be1540, so the same bounded-work ceiling2^120 would no longer imply128bits/query. No registry admission or certificate is inferred for that larger domain.

Remaining review gates are now explicit proof correspondences (unique curve/extraction/selector identities, source nonzero residual and characteristic premises), together with the ROM/multiscope reduction and recursive outer protocol. The arithmetic model is reproducible evidence for review, not a machine-checked proof or an independently approved certificate.
