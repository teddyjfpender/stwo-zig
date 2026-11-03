# Native OM31 outer fold

The outer circuit MAIN remains the original M31 / four-coordinate circuit
witness. The new protocol replaces lookup randomness, cumulative LogUp INTER,
composition and PCS with the concrete octic field. The pinned original AIR
recording remains the constraint authority. One interpreter implements its
native evaluation and circuit-wire evaluation, including the authenticated
four-to-eight INTER lens and unchanged embedded quartic constants.

`rv64_recursion/om31_outer.zig` derives four-tree geometry from the independently
constructed child Authority. It never admits geometry from the proof capture.
The circuit constrains each fixed root to that Authority, reproduces the native
profile/public-output transcript, independently closes the output lookup sum,
then verifies OODS, DEEP, FRI, queries, Merkle paths and grinding. The physical
upper half of every OM31 sample and claim is included. Component random
coefficient offsets are global, matching the native accumulator.

The fold exports a Blake2s digest of a versioned, ordered pair of child
Authority identities and public-output coordinate vectors. Child outputs are
witness wires constrained by verification, never request-specific constants in
the circuit topology. The graph has eight packed-u32 outputs excluding the
mandatory builder `u` output. Odd children should be promoted unchanged by the
driver. Application adjacency, manifest coverage and final execution authority
remain obligations of the execution receiver, separately from this generic
ordered fold.

The qualification receipt is
`vectors/reports/circuit-om31-20261103/fold-root-v1.json`. An actual small native
child proof is verified twice in a fold circuit, that circuit is proved with
native OM31, and an independent receiver accepts its serialized root. Child
public-output, fixed-root and upper-half lookup-claim mutations fail. Mutating
the root output fails a fresh receiver. This establishes a functional fold
foundation, not Ethereum-inventory, production-topology or GPU qualification.
The current fixture intentionally uses one proof twice; distinct-child and
multi-layer tests remain named gates.

The new q108/P20/fold4 identity is a **128-bit security target under documented
assumptions**. Octic challenges remove the single-quartic-field algebraic
ceiling; changing query count alone would not do so. This is not a certified
whole-protocol bound. The final claim still requires explicit algebraic degree,
lookup multiplicity, Fiat-Shamir/grinding and proof-count composition budgets.
A conservative union bound over N independently vulnerable nominal-128-bit
checks subtracts log2(N) bits unless stronger multi-theorem assumptions are
stated. Legacy QM31 profiles and registries are unchanged.

GPU integration can reuse the identical circuit MAIN kernels and native OM31
PCS/lease runtime. The old circuit GPU interaction and StarkWare-specific
transcript path cannot be relabelled OM31. The shared eight-coordinate AIR
walker can record the original constraints into the existing native symbolic
IR; lookup tuple authority should also be shared rather than reimplemented.
