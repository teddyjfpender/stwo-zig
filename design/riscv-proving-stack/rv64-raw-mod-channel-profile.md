# Additive raw-mod M31 sampler profiles

Experimental primitives only. Existing channels and PCS/security profiles are
unchanged. Neither new profile certifies128-bit whole-protocol security; the
QM31 variant must not inherit the nominal96 control's qualification.

Native API: `core.channel.raw_mod_m31.Qm31Channel` and `Om31Channel`.
Call `init()`, then `mixU32s`, `mixU64`, `mixFelts`, `drawU32s`,
`drawSecureFelt` or `drawSecureFelts`. Native OM31 mixing serializes c0 then c1
as eight canonical little-endian M31 coordinates in one digest update.

Circuit API: `native_verifier.raw_mod_channel.Qm31Channel` and `Om31Channel`.
Construction and methods take the existing `(V, ctx, ...)` builder arguments.
OM31 outputs are `Om31Var{c0: Var,c1: Var}` (two QM31 wires); `reduceBlock`
constrains all eight raw-u32 coordinates using the existing packed-u32 reducer.
This is a sampler/channel primitive, not an OM31 PCS/FRI circuit implementation.

Each concrete constructor binds a distinct trusted profile tag before any
application message. Tags include version, modulus, raw word size/block width,
extension degree and bulk packing. `profile.identity()` hashes this authority.
Receiver-owned protocol/key selection must pin it; no production route selects
it merely because an artifact declares its profile. Native proof protocols
using these channels require new domain-separated identities and fixtures.

Every raw draw increments the wrapping u32 counter once; mixing resets it.
No words cause retry. QM31 scalar draws use the first four coordinates and
bulk arrays pack two values per raw block; odd bulk calls discard the unused
half. OM31 draws use all eight coordinates, one value per block. Empty arrays
consume no block. Native/circuit tests compare mixing, outputs, counters and
wrap/reset behavior, and reject a forged upper-half reduction coordinate.

For p=2^31−1, residues0/1 have three u32 preimages and every other residue has
two. Max relative density is rho=3p/2^32<3/2 per coordinate. OM31's eight
coordinates therefore have density at most rho^8≈25.62890615, a4.6797-bit loss.
Under the separately justified condition d≤2^27, the isolated algebraic root
bound is rho^8*d/p^8≈2^-216.3203. This is not the full protocol's security bound:
FRI, OODS, hash binding, Fiat–Shamir grinding, lookup characteristic/mass,
recursion and any union bounds still need their own ledger.

QM31's corresponding four-coordinate loss is2.33985bits, yielding only about
94.66015bits for that same hypothetical degree bound. It is an additive
experimental/control API, not an automatically qualified96-bit replacement.

Boundary reduction is exact: p−1→p−1, p→0, p+1→1, 2p−1→p−1,
2p→0 and2p+1→1. The last two raw words remain forbidden by legacy native
uniform rejection sampling. Legacy in-circuit retry parity remains a separate
unrepaired gate; a new profile does not silently repair or redefine it.
