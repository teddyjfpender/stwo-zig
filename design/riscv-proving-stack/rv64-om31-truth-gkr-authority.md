# OM31 truth authority and global witness producer

This additive, unselected source supplies the service-truth seam for the new
wide-field route. It does not change the production QM31 profile, select GKR for
Ethereum, or establish a whole-protocol 128-bit claim.

## Scope and authority

`services/gkr_local/truth_fractions.zig` enumerates every Keccak χ/xor5 query
(1,920 per row) and every secp byte query, including padding. The Keccak consumers
have negative round-active weight and the fixed providers positive multiplicity;
secp byte consumers have unit weight on all rows and the provider negative
multiplicity. The canonical-input policy omits exactly the original operand
queries. KIO, Wire and RAM remain manifest-challenged global classic relations.

Truth-local challenges have a separate explicit domain, with polynomial and
relation challenges drawn only after the caller seals and binds its own MAIN,
statement, admitted shape and ordinal. The compact producers reuse the original
MAIN tuple/source arithmetic through accessor callbacks. They survive release of
MAIN and retain neither a reconstructed wide row nor tuple planes.

`truth_frame.zig` admits resource and unit-query-mass bounds before allocation.
The current GKR engine materializes row×query facts, clones the inputs and retains
its reduction tree. A Keccak permutation instance at log 18 rounds to 2^29 facts:
its modeled current-engine peak is 73,014,444,032 bytes before its small providers.
It must reject under a smaller budget; this source does not promote that shape
as a memory or performance improvement. A streamed GKR engine or classic local
truth route is needed before admitting that production geometry economically.
The input and core plan charges 136 bytes per fact; binding adds 104 bytes per
row (16 witness and 10 auxiliary M31 columns). MAIN/PCS owner leases are separate.

## Global classic producer

`classic_witness.zig` is shared by truth and CPU global callers. A typed callback
fills secure denominators and tagged base/secure numerators for one logical row.
It supports up to 32 inverse terms and four independently closed physical claims.
Each group stores eight coordinates per inverse followed by eight prefix columns.
All output, two secure scratch matrices and numerator scratch are charged before
allocation. Inversion is batched across 256 rows; prefix accumulation and scatter
remain in logical order. Missing or zero denominators reject even at zero weight.
`take()` transfers the original column backing failure-atomically.

`truth_global_witness.zig` uses the exact original KIO and Wire tuple authority,
provided manifest challenges, and strict single inverses with one joint prefix:
Keccak has 208 interaction columns and secp 32. `truth_global.zig` exposes their
matching degree-three residuals. Endpoint anchors are explicit caller inputs;
the legacy fixed slot/phase selectors are not mistaken for last-row flags.

## Qualification and remaining integration

The focused `test-riscv64-truth-gkr` gate covers all physical rows and query
coordinates against the original MAIN authority, compact metadata after MAIN
release, real native OM31 GKR proofs with fresh verification and terminal MLE
checks, closure failure after changed Keccak state or secp bytes, admission before
allocation, and original KIO/Wire residual satisfaction by generated OM8 witnesses.
It also checks high-coordinate inverse mutation, zero-weight poles, four chunk
boundaries against scalar inversion/prefixes, allocation-failure cleanup and
failure-atomic ownership transfer. Generic KIO/Wire challenge construction and
denominator arithmetic are exercised with dense OM31 values. Legacy QM31 service
and bridge tests remain required controls.

The raw-vector GKR tests do not authenticate those vectors to a committed MAIN.
The joined role binding, receiver-admitted geometry, stage-one manifest, global
closure and complete execution receiver are still required. This module alone is
not a complete accepting VM proof. Production selection and recursion cost gates
remain open; there is no GPU qualification or performance projection here.
