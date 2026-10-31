# Multiplication with a degree-three native domain

This is an additive, closed expected-request component foundation. The legacy
MUL provider and default full Word16 roster retain their existing encoding and
4n domain. It does not prove CPU ingress, global RAM, an Ethereum block, or
recursion. No runtime performance improvement is claimed.

## One integer arithmetic authority

`delegations/multiplication/degree3_provider.zig` calls the existing
`provider.arithmeticFor`, `byteValuesFor`, `tupleFor`, and `activeFor`. The first
141 residuals preserve the old order exactly. No multiplication interpretation,
carry recipe, signed correction, or MULW semantics is copied. The native source
also delegates the old main constructor and retains the same typed requests.

The old 96 BYTE queries use 32 triple-cleared equations of degree four. The new
interaction commits 48 strict pair inverses, one strict typed-request inverse,
and one cyclic prefix. A pair with affine denominators x,y emits
`x*y*inverse - 1`; its contribution is `(x+y)*inverse`. The typed contribution
is `-active*inverse`. Both contributions have degree at most two, and the shared
prefix has degree at most two. The unchanged arithmetic reaches degree three.
Poles are forbidden even for inactive typed padding. There is no witness-side
fraction cancellation that substitutes for an inverse constraint.

The terminal-zero cyclic prefix is initialized by adding the public physical
claim at the first row. BYTE and FUNCTION debts are jointly authenticated, not
separate per-family certificates. The closed receiver independently derives
expected FUNCTION requests, checks `MUL + BYTE + expected FUNCTION = 0`, and
binds both physical claims into Fiat–Shamir before the interaction commitment
and random constraint coefficients. All padded rows retain 96 BYTE queries.
At the admitted maximum log22 their positive query mass is 402,653,184 < p.

## Concrete costs

| Quantity per MUL trace row | Legacy | New |
| --- | ---: | ---: |
| Fixed / main | 3 / 87 | 3 / 87 |
| Interaction | 132 | 200 |
| Constraints | 174 | 192 |
| Current committed cells | 222 | 290 |
| Opened M31 values, including five prior values | 227 | 295 |
| Native quotient evaluation factor | 4 | 2 |
| Current evaluated cells | 888 | 580 |
| Composition split | 2 | 1 |

Committed current cells increase 30.63%; current evaluated cells decrease
34.68%. The bounded n-point current/partner buffers also grow with the column
count: this is not a claim that all resident memory decreases. The new shared
heap row scratch is 18,816 bytes. PCS, coefficients, FFT twiddles, stacks and
caller metadata are additional costs. Previous openings are counted above as
samples, not as an assumed separate full matrix allocation.

A standalone proof also uses `providers/byte_degree3.zig`: the old four BYTE
residuals and 256-row witness are reused exactly, with a separate native2n
loader. The existing BYTE component keeps its old 4n route. This extra adapter
is necessary because standalone components must share a composition split.

## Native and point evaluation

The native loader evaluates two bounded n-point cosets using the qualified
`full/coset_evaluation.zig` degree-three entry. Domain arithmetic uses sixteen
PackedM31 rows and PackedQM31 random accumulation. QM31 remains the OODS lane.
The scalar domain implementation exists only inside test builds, with no
production selector. Column FFTs may use the scoped pool; row evaluation is
currently serial SIMD, not a parallel-row performance claim.

An explicit test runs the complete native evaluator on a different thread
with a 256 KiB WorkPool stack and a null nested pool, comparing every output
coordinate with caller-thread evaluation. This tests the row authority itself,
not merely FFT helpers.

## Qualification

`test-riscv64-multiplication-degree3` runs eight named tests and two wrapper
imports. It covers every arbitrary-Q residual's fourth finite difference,
genuine cubic terms, exact old arithmetic order, scalar/PackedM31/PackedQM31
per-residual agreement, old main/count/debt parity, release-main-before-generate,
strict padding poles, retry phases, exhaustive source/native allocation
failures, the actual bounded-stack worker, and complete scalar/packed proof
byte parity with 1, 3 and 16 workers. A colluding wrong signed-high result fails
the actual closed prover; balanced false physical claims fail verification.

`test-riscv64-multiplication-degree3-circuit` compares all 192 MUL and four BYTE
point residuals with CircuitLane builder wires, including changed alpha,
FUNCTION challenges, claim and count inputs. The arithmetic lane is shared;
this does not claim a new recursive receiver.

The independently pinned 15-request log5 fixture covers all five raw opcode
identities (49, 50, 51, 52, 57), signed/high/W corners and inactive padding.
Safe/Fast emit the same q70/P26 proof, 117,968 bytes, SHA256
`4f44e64452c92f15f5a8f117da4a5daf662d4e82df42a8eb6104225891b4379f`.
Separate fresh processes accept it. The receiver ignores producer diagnostic
request JSON and uses its own expected requests. A new transcript tag binds
the degree, split, and exact physical schema.

The unchanged legacy 80-request log7 proof regenerated byte-identically:
99,864 bytes, SHA256
`a96a11d7b7b03e479ef9eac007910b474474a571c9c6bfa0962079c37ec2c9b3`;
a separately rebuilt old receiver accepts it. These are semantic/component
qualification facts, not evidence of full-roster adoption or a runtime win.
