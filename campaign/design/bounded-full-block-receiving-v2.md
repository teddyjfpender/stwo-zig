# Removing intermediate snapshots from full-block receiving

Design only. The current 139,214,856-instruction run remains unchanged and is
being profiled through its qualified path. Nothing below is an implemented
replacement, a timing result, or a claim that a tenfold speedup follows.

## Recommended route

Use the existing source-local execution theorem with **global RAM OPEN**, give
its endpoint commitment an absolute source ordinal, and close all sources in
one block-wide RAM argument. Initialize RAM once from the ELF/input and add
constrained terminal reads once. Fold these certificates through independently
admitted verifier circuits. Do not carry a complete RAM snapshot at every cut.

There are two distinct milestones:

1. **Snapshot-free receiving:** remove the approximately 2.7 GB intermediate
   state package and snapshot-derived per-window boundary tables. Keep small
   per-source metadata and receiver-reconstructed keys initially.
2. **Bounded public receiving and authenticated circuit registry:** remove the
   remaining per-source key compilation and public metadata from the receiving
   interface. Prove statement reconstruction inside registered leaf circuits;
   use a pinned finite registry and a canonical semantic fold.

Milestone 1 does not, by itself, give a universal fixed VK. Combining it with
Milestone 2 is the coherent target. Merely keeping the present keys and omitting
their snapshot inputs is unsound.

## Existing authority that makes this feasible

`block_v8_endpoint_local_scope_v1.zig` and
`block_v8_endpoint_mixed_scope_v1.zig` do not need incoming/outgoing RAM snapshots
to admit their local originals. Their ledgers prove CPU, registers, local
RAM/clock links, halt guards, ROM and lookups. They export the authenticated
23-column endpoint MAIN root, endpoint count and source identity; global RAM is
explicitly open. See `block_v8_endpoint_local_ledger_v1.zig` and its mixed
counterpart. Caller arithmetic, basic relations, RAM and halt checks remain
mandatory.

`block_v8_endpoint_global_bridge_scope_v1.zig` already fixes the complete ordered
source roster and provider roots before the late draw, retains one epoch across
batches, and supports up to 127 sources in a physical bridge batch. It reopens
the **same** endpoint commitment certified by the original proof. This is the
right seam. A local-z transition scalar cannot be added to another source's
local-z scalar and called global closure.

The present `block_v8_compact_ram_scope_v1.Policy` is not reusable unchanged: it
requires a `Window` and its snapshot-selected table. The new block RAM policy
must replace that authority, with its own identity, count bounds, initializer
and terminal roles. The current closed-window Join also must not be relabeled
as an open-source certificate: its VK still depends on snapshot-derived RAM.

## Canonical statement and certificates

The final statement should have bounded size, for example:

    FullStatement = {
        protocol/version, ISA/ABI semantic identity, security profile,
        allowed_registry_root, program/loader identity,
        ELF digest, input commitment/digest and input length,
        expected_output[43], total_guest_retirements,
        initial CPU/initialization policy identity,
        terminal halt/output policy identity,
        source_count, source_schedule_commitment
    }

The fixed 43-byte output can be public directly; a hash-only output format must
add a proved hash binding. Neither a prover-selected registry root nor a free
initial-memory root is an authorized replacement for the expected statement.

Each registered execution leaf emits a bounded `VM_OPEN` certificate:

    {block_id, source ordinal/range, absolute first instruction, retirements,
     initial CPU, final CPU, endpoint root/count, source identity/local epoch,
     admitted program/profile/geometry identity, initial/terminal role flags}

A Group leaf may emit a bounded list of member endpoint roots and member ranges,
but must retain per-member CPU/register/local-RAM closure. This is optional;
current mixed-Group support must not be assumed qualified.

Other roles are `BRIDGE`, `RAM_SHARD`, `INIT`, `TERM_READS` and `CLOSED`.
Certificates include the exact epoch, range/count and bus claims relevant to
their role. An open certificate never becomes closed merely because its output
was hashed into an upper node. A small semantic certificate is bound to the
verified circuit's output digest; the coordinator verifies that preimage in
circuit before using its fields.

The source schedule is an ordered commitment to all real source descriptors,
including endpoint roots/counts and source ranges. Its construction must be
proved by the fold/roster circuit. A bare prover-supplied digest is insufficient.
No power-of-two filler may count as a real source or retirement.

## One block-wide RAM argument

### Ordering and the late epoch

Number actual execution sources `k = 0 .. K-1` in CPU execution order. Within a
source, existing native/caller memory rules prove its local access order and
compress each address to one `(before, after, last_local_clock)` endpoint.
For the global relation, emit its net transition at coarse time `4*k+3`.
The ordinal is certified by the ordered CPU/source coordinator, not nominated
independently by the RAM prover.

Keep three clocks distinct: absolute guest instruction number, source-local
instruction/access clock, and global coarse endpoint time. Do not repurpose the
current within-window `Frame.global_first_cycle` without changing/reproving its
rebasing rule. A new header can carry the absolute instruction span separately
from the existing local memory frame.

After all source endpoint roots and **all** global provider first roots are
committed, draw the common epoch. Global bridges, RAM shards, initialization,
terminal and range claims use that same epoch. Batch-local redraws or later
insertion of a provider root would invalidate aggregation.

A producer can retain or spool only the narrow endpoint columns/coefficient
representations and net transitions after each local original; it need not keep
all wide native/caller traces. Late bridge openings still require real
committed data. A root alone cannot regenerate those openings. Exact-root
checked disk-backed endpoint leases or bounded bridge batches may be necessary
to avoid retaining every endpoint PCS tree in RAM. This is a new lifecycle to
qualify, not a free consequence of having a commitment.

### Global sorting and sharding

Sort all endpoint transitions by `(address, coarse_time)`. Preserve current
per-address before/after continuity and genuine address/clock range checks.
Do not assume the entire block fits the current single-proof `2^24` event cap.
The total compressed endpoint count is not known merely from the 139M
instruction count.

Partition by disjoint address intervals, with cuts fixed before the common
draw. Canonical cuts should use word indices `a = byte_address / 4` below
`2^28`; emitted memory tuples retain aligned byte addresses. The unit conversion
is constrained, and byte/word aliases are not interchangeable. Each shard proves every row belongs to its interval; all intervals cover
the permitted address domain without gaps/overlap. An address may not be split
between independent shards, otherwise its value chain needs an additional
proved boundary carry. Range cuts can be public small metadata initially and
later committed/proved in the plan certificate. Uniform high-bit buckets may
be badly skewed by guest heap/stack locality.

The aggregate multiset argument consumes every source transition exactly once
across the shards. Counts, shard ranges and real-row activity are constrained;
all claims/first roots are absorbed before interaction commitments. Total
request counts must have independently proved integer bounds below field-wrap
limits. Existing bounds must be rederived for the complete block; lifting a
single-window resource cap is not a proof of a new global census bound.

### Initial values once

At the first global occurrence of each address, prove its before-value comes
from the canonical ELF loader plus the exact input overlay, or from a permitted
zero-initialized region. Derive memory permissions from the same admitted ABI.
An interval containing arbitrary "private input" values is **not** sufficient:
input-region first-touch values must be bound to the expected input.

The old first-touch interval algebra in
`block_v7_initial_algebra_v1.zig` and ELF authority in
`block_v7_initial_intervals_v1.zig` are useful starting points. Their comments
correctly distinguish algebra/table authority from a qualified complete proof.
The new integrated initializer must be proved and recursively admitted.

For snapshot-free Milestone 1, a receiver can reconstruct initialization from
public ELF/input bytes once. For bounded Milestone 2, use either a pinned
program/loader certificate for this retained ELF, or a registered bootloader
proof of ELF decoding/loading and input-commitment binding. A public input root
must be bound to the expected input digest/bytes by such a certificate; choosing
a convenient arbitrary initial root is not allowed. ROM identity and initial
CPU (entry, SP, GP, remaining registers zero) are part of that contract.

### Terminal output once

Do not fix the entire final RAM image. Add thirteen constrained **read-only**
transitions after every real source: halt word 1, length 43 and eleven output
words. Their before and after values are equal and match the expected bytes.
The last word has only three output bytes; its fourth byte is a range-checked
witness carried unchanged, as in the existing terminal algebra.

Use a new coarse-clock system role, e.g. times `4*(K+i)+3` for read `i`, with a
new explicitly bounded policy. Do not silently feed actual guest-cycle terminal
clocks into the old coarse-source policy. The thirteen system reads count as
zero guest retirements and cannot impersonate native/caller sources.

These reads force even a never-touched output cell into sorted RAM: its initial
value must be correct, and continuity proves the read sees the final value.
This avoids the trap of authenticating only terminal addresses that happen to
appear among real accesses. Native first-halt guards still forbid every earlier
nonzero after-value; the last native instruction alone may set halt, and caller
halt accesses remain zero. The terminal reads do not replace first-halt policy.

The mathematical closure is, schematically:

    sum(bridge transition claims) + terminal read claim
        + sum(sorted RAM transition claims) = 0
    sum(sorted RAM first-touch claims) + initialization claim = 0
    sum(genuine range requests) + range provider claims = 0

All use authenticated physical claims under one epoch. Unlike the current
per-window boundary argument, there is no lookup against every window's
incoming/outgoing memory table.

## Why a circuit registry is a second necessary step

The Cairo path provides the pattern, not an already compatible RISC-V key:

- `src/interop/circuit_recursion/registry_definition.zig` specifies the program,
  verifier parameters, supported geometry and shared padding target.
- `src/integrations/circuit_cpu/recursion/leaf_wrap.zig` checks column/config
  shape and the actual circuit hash against the registry on every wrap.
- `canonical.zig` builds and checks the canonical multiverifier; `fold.zig`
  reuses it for bounded reductions. `topology_key.zig` is a cache identity, not
  an authority to approve a circuit.

Current RISC-V keys also depend on exact opcode activity counts, sparse ROM
support and various public-statement constants. Dropping snapshots does not
make those keys static. A legitimate RISC-V registry entry must authenticate
semantic revision, original hash/transcript/PCS configuration, physical columns
and masks, geometry/degree/count bounds, circuit hash/preprocessed root, role
and output ABI. Unknown entries reject. Padding must not increase every native
family to one common maximum height; that would undo independent sizing.

Use statement values as circuit inputs and reconstruct their original transcript
inside the leaf. Complete the typed native/caller AIR and public ledgers around
the qualified native BLAKE3 channel/Merkle/FRI/PCS kernels. The original native
unlifted fold-one configuration is not Cairo's lifted four-tree profile. Outer
circuit hashing can use its own registered suite while the inner native BLAKE3
transcript remains exact. These are different protocol identities, not aliases.

There are two honest ways to admit remaining preprocessing:

1. Make original AIR data-dependent table values genuine witness/public-parameter
   inputs under a fixed semantic verifier, and prove their authority separately.
   Sparse ROM tuples, for example, need membership in the admitted program root;
   moving them from fixed to MAIN columns without that check is unsound. Active
   row counts require Boolean prefix/count constraints, not free inactive rows.
   Simple fixed selector/count polynomials may admit efficient analytic OODS
   evaluation, but circle-domain/shift/order parity and degree soundness would
   need a new qualification before replacing fixed-root admission.
2. Prove exact preprocessing/key derivation under a registered program. This
   includes the actual PCS-domain interpolation, ordering and commitment hashing,
   not merely hashing raw boundary rows. It is possible in principle but can
   be much more expensive than eliminating the snapshot-based tables.

A finite supported geometry registry or a verifier that constrains geometry in
circuit must be chosen explicitly. Merely accepting a witness `VK_hash` or
caching a producer-selected topology does not solve independent admission.

The RISC-V semantic fold must additionally constrain CPU spans, exact source and
bridge coverage, epoch equality and RAM closure. The existing generic Cairo
fold's ability to verify and hash child output digests does not imply any of
these VM-specific obligations.

## Alternative: independent windows with authenticated state roots

A coherent alternative retains per-window RAM closure but replaces full
snapshot SHA identities with an authenticated persistent memory-tree root.
For each touched address, prove its incoming value is in root R_i and prove a
batched authenticated update from R_i to R_(i+1), linked to **all** first/last
RAM tuples. Unchanged touched words still need incoming membership; untouched
subtrees must be preserved. The CPU fold checks adjacent state roots rather
than receiving complete snapshots.

The raw capsule SHA format is not a Merkle-update commitment. This is a new
state model/domain. Existing `air/memory_commitment/blake3_state_tree.zig` has a
30-level full-width u32 memory tree and distinct state-tree framing;
`block_rw_initial_hash_rows_v2.zig` has shared-path row machinery. The qualified
PCS Merkle adapter has another leaf/node domain and cannot be substituted for
state-tree hashing unchanged. Reuse the BLAKE3 primitive and explicit index-bit
constraints, then qualify a state-tree update adapter.

A less structural variant proves the present SHA-snapshot-to-fixed-VK
derivation. It must hash/canonicalize the snapshots, verify all changes and
selection, generate the precise fixed columns, and prove their actual circle
PCS preprocessing commitment and verifier-key relation. A host-generated
boundary-root digest is not enough. This hides receiving data but preserves or
adds the work of materializing every full snapshot and deriving all those keys.

| Choice | Public checkpoint data | Principal new proving work | Main risk |
|---|---|---|---|
| Block-global RAM/open sources | None; initially small source/plan metadata | One shared sorted multiset, initialization once, terminal once, late EP bridges | Global sorting/sharding and durable endpoint leases; cannot claim a source is closed early |
| Persistent state-root windows | Only bounded roots/certificates | Authenticated first-touch/update multiproofs per window | Hash work for every touched path, update completeness and state-tree/key admission |
| Proved current key derivation | None if auxiliaries become private witness | Full snapshot canonicalization/hash plus exact preprocessing/VK computation | Moves the 2.7 GB work inside a proof; may increase total work substantially |

Recommend the first row for this architecture. It preserves the existing
endpoint compression and directly removes the snapshot boundary mechanism.
The state-root alternative is preferable only if independently closable windows
are a stronger requirement than minimizing total memory-proof work.

## Work-removal targets and honest limits

These are places where redundancy can exceed tenfold, not measured end-to-end
speedup claims:

- Replace repeated whole-state serialization/hash/diff/key input with one
  initializer and touched endpoint data. This changes work from repeated
  working-set snapshots toward actual touched state; the gain depends on
  overlap and cannot be inferred from proof file size.
- Replace K snapshot-bound boundary providers and their verifier bodies with
  bounded global RAM shards and batched bridges. Total sorting rows may remain
  comparable, and a larger global proof can cost more; source count alone is
  not a hash-work multiplier.
- Replace repeated instance-specific recursive key/circuit construction with
  authenticated reusable leaf classes and a canonical fold. Existing Cairo
  topology/preprocessed caches demonstrate the lifecycle, not RISC-V timing.
- Prove ELF/input initialization once rather than rebuilding it at every
  window and every recursive receiving traversal.

The native/caller arithmetic and most source MAIN cells remain. Load/store and
basic ALU representation, caller composition and native proof openings still
need their own reductions. Eliminating snapshots cannot imply a tenfold gain
for stages it does not remove. Shared ROM/range/lookup epochs are possible
later, but late projection of wide native/caller commitments needs retained
committed data; it is not the narrow endpoint optimization for free.

Neither snapshot removal nor a registry automatically gives zero knowledge.
Trace blinding, commitment opening leakage and input privacy require separate
protocol choices and tests.

## Critical negative and end-to-end gates

Before admitting a new route:

1. Real two-source native/mixed execution without intermediate snapshots, then
   q70/26 original and one-root fresh receiving from ELF/input/output plus the
   explicitly declared small metadata. Include FIRST instruction and terminal.
2. Alter an endpoint root, value or ordinal; duplicate/drop/reorder a source;
   use gaps/overlaps or wrong CPU boundaries. All reject.
3. Use different epoch draws across bridge/RAM/initializer batches; insert a
   root after drawing; reuse a bridge slice or omit one. All reject.
4. Forge a first-touch value in zero, ELF-data or input regions, including an
   unchanged read. Omit input authentication or change the input digest. Reject.
5. Omit a terminal address never touched by the guest, change output/length/halt,
   change the tail high byte through a purported read, count a synthetic read
   as retirement, or write halt early then clear it. Reject.
6. Overlap/gap address shards, split one address's history, omit boundary carry,
   use noncanonical order/clocks or field-wrapped counts. Reject.
7. Supply an unknown VK/circuit/geometry, remove a mask/claim/caller/guard,
   alter a preprocessing sample, or hash a certificate whose semantic preimage
   is not checked. Reject. Topology/value rebuilds must agree exactly.
8. Destroy original proofs, witnesses, profiles and producer keys; receive only
   the final artifact and the newly specified public inputs/registry. Do not
   silently load the old checkpoint package or accept its cached keys.

Use a new protocol/schema/output ABI throughout and preserve the current
qualified full-block path as the baseline. The live run establishes the real
cost profile before any of this design is turned into production mathematics.
