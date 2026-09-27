# Narrow BLAKE3 rotation precompiles

This experiment follows the rejected wide-round candidate. That candidate's
q70/PoW26 comparison increased next-level path work by 20%, so it is archived
rather than promoted. The shared narrow G component remains the canonical path
for execution commitments and native recursion.

ZisK's `ROTR7(x) = ROTL1(ROTR8(x))` construction suggested a useful M31 adaptation.
The same bounded-limb approach also simplifies ROTR12. Both use byte permutation
for ROTR8 and two 16-bit limbs for the remaining rotation. Native BLAKE3 outputs,
protocol framing and fixed security parameters stay unchanged.

| Per G row | Before | Candidate |
| --- | ---: | ---: |
| Main columns | 112 | 90 |
| Direct constraints | 56 | 32 |
| Arithmetic lookup events | 52 | 46 |
| Total events including caller wires | 62 | 56 |
| Interaction columns | 124 | 112 |

These are 19.6% fewer main columns, 42.9% fewer direct constraints and 9.7% fewer
total events. Combined main/fixed/interaction width falls 252 to 218 (13.5%). These
counts are not an end-to-end timing claim. All ordinary users of the shared
component receive the change without a benchmark-specific switch.

## Integer soundness

The XOR lookup bounds every source byte. Output bytes are range-checked. Write
`y = ROTR8(x)` as 16-bit limbs `y0,y1` and output as `r0,r1`.

- ROTR7 uses boolean carries `c0,c1` and the two equations
  `2*y0 + c1 = r0 + 65536*c0`, `2*y1 + c0 = r1 + 65536*c1`.
  Each side is below 2^17. Reduction modulo 65536 pins the rotation; the boolean
  carries are the high bits of the respective input limbs.
- ROTR12 uses four-bit carries bounded by the existing `(c,16*c)` byte-pair
  lookup: `y0 + 65536*c1 = 16*r0 + c0` and the symmetric second-limb equation.
  Each side is below 2^20. Reduction modulo 16 pins the low nibbles and then the
  output limbs. All bounds are strictly below M31, preventing field aliases.

The witness emitter follows exactly the same layout. The typed arithmetic and
caller semantic digests are repinned; existing statements still bind all caller
inputs/outputs and multiplicities. Proof bytes/keys may change with AIR geometry.

## Evidence

The rotate7-only pilot passed 21 focused tests and four real-proof checks.
The combined candidate passes the same 21 focused tests, including every-coordinate
mutations, native/reference equivalence, all seven rounds, partition wire closure,
and direct-compiler checks. Six real-proof tests also pass with the interim wide
fixture included (empty, partial, unbalanced chunk tree and framed Merkle node).
After removing that rejected fixture and its infrastructure, the final narrow-only
root passes 18/18 tests (`final-light-safe.log`). Final full-hash and CPU/Metal
canonical-tree qualification and matched timing are recorded below as they complete.

The wider compiler/runtime changes needed only by round fusion are removed from
the live path. Its source and results remain in the neighboring typed-round archive.
The frozen tree control is the previously qualified two-child preparation candidate;
each timed arm uses its matching archived authenticated AOT bundle, with eight CPU leaf workers,
two child-preparation workers, q70/PoW26 and the same four-leaf workload.

This note's directory retains the initial ROTR7 name; the final candidate includes
both non-byte-aligned rotations. No full CSP basket or subsecond recursion claim
follows from the primitive qualification.

## Device integration

The first canonical four-leaf run verified all seven checks but used the previous
AOT catalog: the changed G identities were absent, so interaction/composition fell
back to CPU. This is retained in `old-aot-fallback-qualified.log` and the one-second
sample showing the host G evaluator. It is not a candidate performance result.

Both catalogs were regenerated from the authenticated typed AIRs. The two changed
G kernel identities were synchronized into the core export manifest and Objective-C
pipeline initialization, declaration digests updated, and core ABI advanced 23 to
24. Core source SHA256 is
`2908f52d54516a3b3586a6502799b050e051957a7c2622111b5f65ced4ba9e07`.
Eight shader-authority checks pass; device acceptance verifies all 199 exact exports,
zero function constants and AOT/JIT parity. The generated-catalog check also passes.

The canonical Metal tree gate now preflights the exact admitted interaction and
composition kernels for all eight native hash components before any proof work.
A stale kernel catalog therefore fails immediately instead of silently qualifying
an expensive CPU fallback. Timed candidates must additionally show 28-batch G
interaction dispatches. The control uses its frozen ABI23 library; the candidate
uses the newly accepted ABI24 library. AIR/key and kernel changes are intentional.

## Matched canonical tree result

All twelve timed aggregate artifacts independently verify at q70/PoW26. Four-leaf,
six-cycle workload, two aggregate levels; one tree at a time, eight CPU leaf workers
and two root-preparation workers. This is not an Ethereum-block or CSP timing.

| Arm order | Complete fixture seconds |
| --- | ---: |
| control | 41.893 |
| candidate | 40.670 |
| candidate | 40.509 |
| control | 44.512 |

Median complete fixture: **43.202 → 40.589 s**
(6.0% reduction). Both candidates are faster than both controls, but there are
only two samples per arm and visible control variance. This is a modest local gain,
not an order-of-magnitude improvement or proof of superiority.

Peak physical footprint: **44,451,505,064 → 38,974,904,880 bytes**
(12.3% reduction). Routed allocation peak falls 29,486,122,073 to
26,459,992,736 bytes. Retained root rows fall 4,940,200,960 to 4,199,425,192 bytes.
Artifact sizes become 845,993 / 849,496 / 889,364 bytes, versus
853,044 / 850,623 / 903,838 in the control.

| Phase median | Control s | Candidate s |
| --- | ---: | ---: |
| Left leaves + preparation | 6.105 | 5.907 |
| Left aggregate + checks | 5.998 | 5.575 |
| Right leaves + preparation | 6.452 | 6.286 |
| Right aggregate + checks | 6.007 | 5.482 |
| Root preparation | 4.668 | 4.312 |
| Root aggregate + checks | 13.270 | 12.336 |

Retained in the shared default path. Full CSP validation is recorded separately;
these tree results do not supersede historical Poseidon CSP measurements.

## Full local CSP qualification

All 32 positive CPU/Metal cases and both invalid-signature rejection proofs pass,
with separate fresh artifact verification. M5 Max, ReleaseFast, q70/PoW26,
blowup 1, fold step 1, last-layer degree 0; one sample per case and zero warmups.
The environment requests 16 CPU/Merkle workers; ECDSA explicitly requests and
reports 16. These are local dirty-tree qualification observations, not published
CSP scores, stable medians or a replacement for the historical ten-sample suite.

Execution+witness+prove matches the historical timing scope. Complete time also
includes admission, artifact encoding and fresh verification. It excludes process
startup and the separate retained-artifact verification command.

| Workload | CPU execution+witness+prove (s) | CPU complete (s) | Metal execution+witness+prove (s) | Metal complete (s) |
| --- | ---: | ---: | ---: | ---: |
| SHA256 / 128 | 1.434585 | 1.863756 | 0.949233 | 1.402213 |
| SHA256 / 256 | 1.607891 | 2.052948 | 0.986743 | 1.440661 |
| SHA256 / 512 | 1.699606 | 2.156262 | 1.027794 | 1.487084 |
| SHA256 / 1024 | 1.540815 | 2.007271 | 1.064012 | 1.537355 |
| SHA256 / 2048 | 2.545874 | 3.129200 | 1.587823 | 2.160417 |
| Keccak / 128 | 2.358332 | 2.910075 | 1.474446 | 2.023495 |
| Keccak / 256 | 2.491983 | 3.060456 | 1.524815 | 2.064038 |
| Keccak / 512 | 2.528864 | 3.100374 | 1.559536 | 2.103476 |
| Keccak / 1024 | 2.921106 | 3.499611 | 1.686181 | 2.239998 |
| Keccak / 2048 | 2.917653 | 3.534500 | 1.820710 | 2.401642 |
| Poseidon2 M31 guest / 2 | 0.660669 | 0.816369 | 0.394154 | 0.548717 |
| Poseidon2 M31 guest / 4 | 0.926435 | 1.083843 | 0.504163 | 0.661220 |
| Poseidon2 M31 guest / 8 | 0.928582 | 1.087194 | 0.617456 | 0.774051 |
| Poseidon2 M31 guest / 12 | 1.186136 | 1.344126 | 0.727847 | 0.884671 |
| Poseidon2 M31 guest / 16 | 1.146036 | 1.313647 | 0.838370 | 1.000733 |
| ECDSA precompile / 32 | 0.715774 | 0.860641 | 0.495651 | 0.646243 |

The bad-signature software guest executes 5,428,253 instructions and proves a zero
rejection output: CPU 10.852153 s, Metal 8.248589 s in the execution+witness+prove
scope (complete 12.445523 / 9.798151 s). This is separate from the positive ECDSA
precompile guest, which executes 1,828 instructions. The negative case does not
contribute to the positive basket's timings.

The publication runner first refused dirty trace provenance. Its cleanliness gates
were not relaxed. `qualify-csp.py` follows the earlier local research pattern,
records `implementation_dirty=true` explicitly, authenticates the canonical guest
and input manifests, inspects serialized proof security parameters, checks exact
public output/cycles and independently verifies each retained artifact. Binaries
and the matching AOT library are frozen with hashes. A clean HEAD trace executable
provides independent execution checks for the software guests; the typed ECDSA
precompile's cycles/output are bound by fresh proof verification, as in the
maintained benchmark runner, because that base trace product lacks its capability.
The initial capability failure is retained, and the driver resumed completed cases
only after checking their frozen executable hashes.

This full local qualification does not establish recovery of the historical
Poseidon CSP performance basket. Further recursion performance work remains open.
