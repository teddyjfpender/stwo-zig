# Word16 DIV with shared unsigned-product truths

The production core schema5 uses one82-MAIN/76-INTER DIV row with192 residuals
of degree at most3, on native2n. The previous independently sized DIV row had
1135 MAIN/8 INTER columns and1567 residuals. Integer division is reduced to
canonical limb arithmetic and two ordinary unsigned MUL/MULHU FUNCTION requests.
There is no new execution profile, ECALL, accepted hint or instruction semantic.

The provider emits `-DIV(A,B,C) + MUL(Q,absB,productLow) +
MULHU(Q,absB,productHigh)`, with unit weights on active rows. The existing MUL
provider establishes the full128-bit product and canonical Q/absB/product limbs.
DIV enforces productHigh=0, productLow+R=absA with a zero terminal carry, and
R<absB through a ranged strict difference and zero final borrow. These facts
establish unsigned quotient uniqueness in integers, including absence of64-bit
product wrap. The high product obligation is essential even when the low product
looks correct.

A/B/C, absA, R, the strict gap and normalized output limbs have explicit U16
anchors. Signed input/output normalization uses Boolean carries. Each integer
limb residual has magnitude below2^18, far below M31, so a field equality cannot
hide an integer carry alias. absB and Q canonicality comes from the closed MUL
support graph; local DIV residuals alone are deliberately insufficient.

Signed/unsigned64-bit and W policies use the same authority. W selects low32
inputs; garbage upper input bits have no effect. The selected top-limb sign
query is `2*top-65536*sign` into U16. Each selected top is quadratic in the W
selector and input limbs, so its lookup uses a strict individual inverse.
Restoring the signed quotient/remainder naturally handles MIN/-1 overflow.
For a zero divisor, Q=0 and R=absA; quotient output is independently forced to
allones while remainder restores the input. W results are sign extended from
bit31, including unsigned W instructions.

There are31 U16 queries per PHYSICAL row, including padding. The remaining29
linear U16 denominators and three linear FUNCTION denominators form16 strict
pairs. Two quadratic sign-query denominators remain single. One cyclic prefix
closes the combined debt:16 pair inverses +2 single inverses +1 prefix =76
base coordinates. Claims must enter the transcript and close with every caller,
MUL truth and canonical U16 provider; additive subrelation splits are not
independent certificates.

Native MAIN is constructed once. A96-byte metadata record retains only11 query
words, opcode and sign flags after MAIN destruction. Interaction generation
uses the same denominator and contribution expressions; it does not rerun
normalization, integer multiplication or carry generation. Owned/borrowed paths
share a filler and preserve caller buffers on failed construction.

Prepared advice adds exactly two real unsigned support requests per DIV while
preserving raw retired MUL counts separately. MUL provider capacity can reach
2*CPUsteps; its independently bounded maximum native log is23. CPU and other
caps remain22. Native admission bounds counts and all FUNCTION/R16/R8 masses
before proof allocation; MUL's existing96 byte requests per physical row remain
part of that accounting. The protocol mixes schema5 and actual layout widths.

The shared degree3_domain kernel owns native SIMD cosets, previous-row halos,
weight accumulation and additive output placement for both MUL and DIV. Each
concrete adapter supplies its own polynomial evaluator; no integer semantics
are copied into the kernel. The point evaluator supports external circuit
lanes with dynamic count, claim and challenge wires.

For the retained block,17 DIV instances contain6270 active/8704 padded rows.
The narrower DIV saves8,573,440 native cells, but668 extra support requests in
CPU shard13 cross the MUL power-of-two boundary and add9,502,720 cells. Net native
cells INCREASE929,280 (about0.0044% of the block). The intended improvement is
16,745 fewer OODS samples (1151->166 per DIV component) and lower opening and
recursive arithmetic work, not a source-cell multiplier.

Qualification covers all8 policies against an independent signed-integer oracle
on extrema/random words; dense degree tests; scalar/PackedM31 parity; actual
Circuit point/claim/challenge/count/point mutants; ownership/OOM/poles; honest
joined physical proofs/fresh verification; and actual locally valid low- and
high-product attacks rejected only by the complete FUNCTION closure. Sail and
ECDSA preserve CPU/RAM/image/program semantics; the real services prefix covers
Keccak, ADD and DOUBLE joins. New schema5 bytes intentionally differ from old
schema4 fixtures. Full-block qualification and controlled performance remain
separate gates; no recursive root or128-bit whole-protocol claim is made here.
