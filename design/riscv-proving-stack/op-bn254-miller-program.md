# OP BN254: costed Miller-program boundary

This is a design/census, not an admitted service. The qualified 640-byte
Miller-line client keeps its existing tag and profile. Do not emit a second
service or widen its admission from this document.

## Evidence and next boundary

OP block 121065789 executes 253,185,635 instructions after the LRU and
640-byte line client changes, versus 380,167,068 in the selected baseline.
The native executor and independent Unicorn agree on exact steps, terminal PC,
all registers, service counts and the expected 43-byte output. Physical proving
of the new OP provider is still a separate gate.

The remaining tower program is substantial:

| Operation | Actual count | Existing Fp2 multiplication calls per operation |
| --- | ---: | ---: |
| Miller invocation | 85 | variable |
| Point-scaled sparse line | 22,185 | moved to new service |
| Fp12 square | 5,439 | 12 |
| Dense Fp12 multiply | 2,266 | 18 |
| Fp6 general multiply | 17,676 | 6 |

These counts come from entry PCs in the complete executable census and the
pinned Arkworks formulas. The Fp6 identity is
`17,676 = 2 * 5,439 + 3 * 2,266`; the two lower rows overlap and must not be
summed. An operation using a zero/one shortcut may emit fewer actual services
than the nominal formula. The 106,056 nominal Fp2 calls attributed to dense
multiplication and squaring are an opportunity, not a measured removal.

There are 84 seeded request loops and one unseeded cached-factor construction.
BN254's fixed signed ATE loop has 64 iterations, 21 nonzero interior digits and
87 line evaluations (64 + 21 + two Frobenius correction lines). Thus squares
are `84 * 64 + 63 = 5,439`. The 255 effective point contributions account for
`255 * 87 = 22,185` lines. Dense products comprise 1,764 signed-seed products,
84 seed/inverse checks, 336 residue-tail products and 82 cached-factor merges.
A Miller-only program does not subsume the inverse, tail or factor merges;
its own dense products are the 1,764 signed-seed products.

The client still retires 34.9M self instructions in Fp6 multiplication,
23.3M in Fp2 addition and 8.4M in Fp12 squaring. Function self counts exclude
callees. Client-independent execution remains significant: the EVM dispatch
function alone has 28.4M self instructions. An 80–100M ordinary-client floor
is an estimate until the shared routines have call-stack attribution.

Read-only Unicorn entry probes independently reproduce the same machine
execution. Return-PC attribution observes 236,222 memcpy calls requesting
34.56 MB, 224,750 memcmp calls requesting 7.39 MB and 44,144 memset calls
requesting 7.23 MB. Explicit pairing/Ark callers account for 22.92 MB of
memcpy and 6.12 MB of memcmp requests. The 22,185 line packets alone copy
14.20 MB, and Fp12 squares copy another 5.22 MB. These bytes are not an
instruction-cost model; tail calls preserve earlier callers' return PCs.

## Narrow program, not a monolithic equation

Keep canonical point parsing, on-curve and subgroup checks, cache ownership,
G1 grouping and normalization in the guest initially. Replace exactly
`miller::run_skipping` with a fixed, bounded field microprogram. Include both
seeded and unseeded entry modes. Prove the signed ATE schedule and both final
Frobenius lines from immutable program ROM. Do not assume the intermediate
Miller accumulator is unitary or cyclotomic.

Use narrow arithmetic rows with a typed local field-value bus. Program-local
accumulator temporaries must not cross the global RAM argument each operation.
A field-result identity must bind program invocation, instruction index,
value identity, limb position and canonical value; producer multiplicities and
consumer closure must be explicit. Program ROM, operation schedule, branch
masks, address reads and final output must all bind to the request. Every
private modular reduction retains source-derived strict M31 residual and
carry bounds. A small column count without these bounds is not a design win.

Prepared coefficient arrays and G1 coordinates remain guest-produced,
RAM-authenticated inputs; supplying a pointer is not authority for their
values. Read each coefficient at its actual address, with checked pointer
arithmetic, bounds and readonly alias semantics. An Arc-owned coefficient
array may be reused across requests, so global RAM reads must preserve the
actual address/value/timestamp semantics rather than invent duplicate writes.
Return only a canonical Fq12 accumulator. Do not accept a host-supplied pairing
Boolean, prepared value or cached answer.

A data-volume model for the observed workload has 133,110 coefficient Fq,
510 G1 Fq, 2,016 seeded input Fq and 1,020 output Fq. This is 4,372,992 bytes
including output, before descriptor overhead, versus 22,717,440 bytes read
and written by current line packets alone. The model allows one bounded
program invocation for each current loop, not an unbounded host computation.

## Semantics that must remain in the authority

- Parse canonical base-field encodings. All-zero affine pairs represent
  infinity under the existing precompile semantics; arbitrary malformed points
  do not. Validate G2 even if its accompanying G1 is infinity.
- Preserve both on-curve and subgroup checks, including checks for newly
  encountered points after eviction. Exact-byte guest caches only reuse
  computations established in this execution.
- Preserve empty groups, canceling grouped G1 points, skipped factor masks,
  signed seed selection and unseeded factor construction. Check mask bounds
  against at most 16 groups. Do not add an unchecked prepared-line cache.
- Keep the seed/inverse validation and residue-tail check. Bad/missing advice
  must follow the existing full computation and final exponentiation fallback;
  false pairing results must remain false. A positive hint is not a Boolean
  oracle.
- EVM call validation and gas charging stay outside the arithmetic service;
  cache hits must not suppress charging, fork selection or malformed-input
  behavior. Oversized requests retain the bounded software fallback.
- Check packet/descriptor alignment, ranges, overflow, input/output aliasing,
  canonical output, readonly tails and service completion. Keep witness memory
  bounded per invocation and prohibit old profiles from accepting new tags.

## Qualification order and open decision

First qualify the narrow line provider under the existing 640-byte interface:
physical valid/forged proofs, whole RAM and service closure, receiver geometry,
and fresh receiver acceptance. Compare native cells, main/interaction columns,
opening masks, witness memory and recursion cost against both the old Fp2 lane
and the wide reference; cells alone are insufficient.

Then build a standalone fixed-program prototype with an independent tower
oracle and exact program operation counts. Test seeded/unseeded loops, zero
and infinity inputs, cancellation, all mask positions, malformed coefficients,
wrong inverse/tail, output mutation, local-bus omission/duplication and
cross-invocation substitution. Only after costing that prototype should a new
request ABI or tag be proposed. A complete pairing boundary could absorb G2
preparation and residue-tail arithmetic later, but has a larger validation and
false-result authority surface than this first Miller boundary.

The hard 10x end-to-end target is not established by these execution counts.
Remaining client retirements and recursion must both fall substantially; a
34% retirement reduction is not a 10x proving claim.
