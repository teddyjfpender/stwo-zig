# Services local GKR custody and binding authority

This is additive source for the new OM31 protocol. It does not select a new
Ethereum prover or accepting receiver. The current QM31 services route remains
unchanged. Numerical GKR verification returns `Pending`, whose terminal MLE
obligations must be closed by the physical STARK before execution acceptance.
It establishes neither a whole-protocol 128-bit claim nor a speedup.

## Concrete source authority

`services/gkr_local/fractions.zig` is the raw local numerator/tuple authority.
`dispatch.zig` selects it for actual CPU/family/table/bridge MAIN projections.
`native_provider.zig` reads the existing durable `services.roster.Sources` advice:
CPU56B, ALU54B, BINARY46B, SHIFT30B, LS82B, DIV88B, MUL requests, service packets,
ROM/public register endpoints and the already retained count histograms. Its
scratch is one row or tuple. It neither retains detached MAIN nor expands its
coefficients. The source matrices can be consumed by owned commitment and
modified in place without changing any of these queries.

The complete CPU-shard local roster contains REG and its public32-row boundary,
ROM, FUNCTION and every arithmetic/binary/shift/JALR provider, OWNER and all
load/store/Keccak/secp bridges, U16/U8/AND/SHIFT/selection tables. INIT/TEARDOWN
have no local fraction debt. RAM, Keccak IO and secp Wire remain explicit global
obligations; this code cannot discharge them. Separate Keccak/secp truth PCS
local lookups still require their own roster/profile conversion.

Byte-query alpha equals the U8 offset and the U8 coefficient is fixed to one,
matching the existing trusted arithmetic-bus policy. MUL's byte tuple is
projected affinely to the canonical13-coordinate FUNCTION tuple, preserving the
old negated-coefficient sign. Every padded-row range query is retained. Inactive
zero-weight fractions retain their denominators, and root denominators must be
nonzero even for a zero numerator; no proof-dependent redraw is permitted.

## Ordered custody

1. Production integration must seal FIXED and MAIN first. The local transcript
   binds those roots, trusted statement/program digest, ordinal and derived roster.
2. Local relation draws produce actual M31 numerator and OM31 denominator MLEs.
   Rows use physical circle storage; lanes are the low bits. Missing lanes are0/1.
3. The existing OM31 core proves all local instances, then the child receiver
   reconstructs its transcript and output closure. The canonical receipt frames
   scope, field degree, ordered roster, proof and reconstructed terminal marginals.
4. GKR's common point is sliced by each instance's complete variable count
   FIRST, then split into row prefix and lane suffix. This matters at mixed logs.
5. Eta is drawn after the terminal marginals. Each instance has its own Eq and
   prefix witness binding N+eta*D to that instance's MAIN masks. No cross-instance
   marginal cancellation stands in for per-instance authentication.
6. The future stage-one manifest entry must bind the child receipt and marginals
   beside its roots. Only the ordered COMPLETE entries may derive global
   RAM/KIO/Wire randomness. Fresh acceptance must verify the child and every
   physical binding, all global claims, coverage, endpoints and public boundaries.

`receipt.emitCanonical` is the common native/circuit framing visitor. A circuit
writer must constrain field-coordinate canonical encodings. `closure.closeFor`
is shared native/circuit algebra and enforces strict root-product nonzero checks.
A digest by itself is not proof verification.

## Memory and ownership

The caller must supply a nonzero hard local GKR allocation cap. The owner is
heap-stable and uses the existing HostBudgetAllocator for all input, core clone,
product-tree, proof and binding allocations. All failure paths retain cleanup
ownership. The cap covers those owned allocations, not source advice, pool stacks,
PCS scratch, allocator-retained mappings or process RSS; those require separate
admission. No global cache is added.

The up-front plan includes36 bytes/fact of raw inputs and conservative100
bytes/fact of cloned/higher-layer storage, and64 bytes/row of16 base binding
planes. The cap remains authoritative if smaller proof/helper allocations exceed
that estimate. Eq construction writes directly into column-major base planes;
only128 OM31 lane weights live on the stack. Prefix construction consumes the
already-built input vectors before releasing them; it does not rebuild the wide
witness or replay tuple planes.

This is a real resource issue, not a performance result: CPU log22 with16 query
lanes alone budgets9.13 GB for inputs plus the current cloned product hierarchy.
Whole-shard scope is larger. Streaming/layer-lifetime improvements are required
before claiming a5 GB GPU batch budget for this representation.

## Qualification and remaining acceptance gates

The focused suite exercises original chip and bridge query projections, padded
lane handling, mixed-height point slicing, strict poles, unbalanced closure,
scoped child transcript tampering, bounded ownership and allocator failures.
Actual two-shard services fixtures compare metadata fractions to physical MAIN
for every present core/table/K/ADD/DOUBLE role, then overwrite every detached
owned-MAIN backing and repeat the queries.

Remaining gates are a SINGLE per-role MAIN span combining original arithmetic,
Eq/prefix binding and actual OM31 global interactions; original fixed-table and
ROM arithmetic admission constraints; native and circuit physical masks binding;
stage-one manifest/wire/receiver integration; separate truth PCS local profiles;
physical-invalid-witness tests; and whole-block semantic/fresh-verification
qualification. No helper test makes those remaining obligations optional.
