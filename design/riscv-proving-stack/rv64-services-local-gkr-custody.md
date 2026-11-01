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
3. The local root closure is one batched rational-sum identity across independently
   random relation namespaces. It does not assert exact per-relation marginal
   claims. Its exceptional-event/degree bound belongs in the protocol security
   ledger; exact per-relation claims would need a different authenticated
   partition/binding construction. The existing OM31 core proves all local
   instances, then the child receiver
   reconstructs its transcript and output closure. The canonical receipt frames
   scope, field degree, ordered roster, proof and reconstructed terminal marginals.
4. GKR's common point is sliced by each instance's complete variable count
   FIRST, then split into row prefix and lane suffix. This matters at mixed logs.
5. Eta is drawn after the terminal marginals. Each instance has its own Eq and
   prefix witness binding N+eta*D to that instance's MAIN masks. No cross-instance
   marginal cancellation stands in for per-instance authentication.
6. `manifest.verifyAndSeal` now verifies each actual local child and binds its
   receipt and reconstructed marginals beside every worker's roots. The complete
   ordered roster includes explicit classic-local OM31 truth slots. Only then
   does it draw separate OM31 RAM14/KIO11/Wire35 challenges. This returns a
   **pending** manifest, never execution acceptance. The accepting assembly must
   still verify every physical proof/binding, all global claims, coverage,
   endpoints and public boundaries.

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

The first physical gate now exists in `role.zig` and `role_domain.zig` for the
eight computed CPU families. Original MAIN residuals and three binding residuals
share one physical MAIN span and one bounded2n expansion. Domain residuals use
packed M31 for original arithmetic and packed OM31 for the secure binding. The
Eq carry and first/second selectors are derived ephemeral polynomials, not new
trusted witness columns. There is no second MAIN FFT for binding.

The actual varying ALU witness proves47 MAIN columns plus13 local query lanes
and16 binding base planes through full OM31 composition, PCS, FRI and a fresh
core receiver. An active MAIN multiplicity can be changed while all original
ALU arithmetic residuals remain zero; the physical local binding rejects it.
Independent target, Eq and prefix changes also reject. This is a local fragment:
its nonzero FUNCTION/range debts do not become an execution acceptance claim.
The full source catalog, bridge/global joining and complete manifest receiver
remain separate gates.

Instances with different lane counts generally have different row-point
suffixes. No Eq column is shared solely because roles or row logs agree.
Affine-fraction pairing and better lane-height partitioning are future measured
resource optimizations; neither is applied implicitly in this version.

Binding ownership now crosses the existing owned PCS seam explicitly. N/D,
cloned GKR layers, proof and artifacts remain allocated through the stable local
budget owner. Eq/prefix planes use the parent worker allocator with an external
reservation charged against the same local cap. `takeBindingCommit` allocates
and validates headers before releasing source custody; failure preserves the
planes and reservation for retry. Success transfers the existing plane pointers
to the worker's owned committer, then releases only the local reservation. The
receiving worker must continue charging that live storage; no RSS drop is claimed.
This avoids an allocator mismatch and a whole-binding-witness copy.

`global_cpu.zig` retains the separate physical RAM/KIO/Wire debts. Its widths
are16 global base columns for LS/INIT/TERM,32 for Keccak bridges and56 for secp
bridges, in addition to local binding where present. RAM/KIO affine fractions
use strict paired inverses plus joint prefixes; secp Wire's quadratic after
weight uses an independently claimed cleared pair. Original tuples and signs
are shared across native and authenticated arithmetic. Claim-vector conversion
and native absent-field checks prevent free absent cancellation debts. The
new accepting role constructors must invoke those checks before worker sums.

The INIT/TEARDOWN20 direct MAIN residuals now have their own shared seam; legacy
constraint ordering is retained and the existing55-test memory suite passes.
Global CPU authority has degree-three, layout/prefix-mask and zero-weight-pole
gates. These are authority gates, not a completed global service proof route.

## Shared table bindings and manifest (integration slice)

`role_domain.zig`, `role_oods.zig` and `role_geometry.zig` now share the packed
composition, OODS and mask authority across the core and table roles. Statically
selected emitters provide original arithmetic and raw query projections; trusted
per-component capacity constants bound scratch. There is one original MAIN
span and one bounded expansion. The table wrapper covers ROM, public REG,
U16/U8, AND, SHIFT and selection. ROM retains its invalid-row multiplicity guard.
Fixed values remain authenticated immutable setup polynomials; no redundant
in-chip table-value constraints are introduced.

Public REG takes validated native statement words and uses the existing shared
literal/tuple arithmetic at both packed domain rows and OODS. It does not treat
an arbitrary OM31 public word as a packed M31 value. Real ROM, U8 and public-REG
fragments prove and freshly verify; stale U8 multiplicity and changed register
endpoints reject. All seven table query emitters compare native OM31 against
sixteen distinct packed M31 rows, including all eight secure coordinates. These
fragment tests do not claim whole-local closure or full-height physical proofs
for each remaining table.

The manifest's expected worker list, statement identities, FIXED roots and
relation-presence masks must be reconstructed by the receiver from admitted
setup and execution, never copied from producer declarations. MAIN roots are
stage-one commitments and must match the later freshly verified PCS roots.
CPU-local GKR is mandatory in this initial profile; truth locals explicitly use
OM31 classic arguments. A truth-GKR selection requires a separately admitted
profile. Missing/reordered children, changed scopes/rosters/receipts and invented
truth children reject before global randomness is used.

Each global relation closes separately. Nonzero claims in absent worker
relations reject even when another worker cancels them. The assembly must also
validate presence and transcript binding for **each physical role** before
aggregating worker claims; this helper cannot authenticate producer host sums.
The manifest digest commits reconstructed terminal marginals as well as the
canonical child proof receipt. Its algebra and framing are implemented, but
complete bundle-wire, physical-role assembly and accepting execution-receiver
integration remain pending. This is not a whole-protocol 128-bit certificate.
