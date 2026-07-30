# Session 18: SN2 authenticated multi-arena quotient

Date: 2026-07-25

## Scope

This increment connects the exact Cairo PCS quotient topology to the resident
CUDA memory model. It fixes a semantic count conflation and proves the new
multi-arena, compact-output numerator path against an independent CPU
reference on an RTX 4090.

It does not claim a complete SN2 CUDA proof or a proving-speed result.

## Exact PCS topology

The topology compiler derives the quotient workload from the authenticated
composition bundle, proof program, and compact protocol. For SN PIE 2 it
produces:

```text
sampled values       6,110
prepared terms       6,342
periodic terms         232
point groups             19
resident sources       5,886
packed partial words 20,971,472 per coordinate
largest partial rows  8,388,608 (2^23)
final quotient rows  16,777,216 (2^24)
source LDE words     7,434,440,576 across four trees
topology identity    17ae45e9aa7cc5975f65d6dd67d761501f9284bd6ac6e7de861ce1f2ab272d2b
```

The previous resident plan incorrectly used the AIR schedule's 1,325
constraints and 58 components as PCS term and group counts. Those quantities
describe constraint evaluation, not quotient sampling. They cannot size the
prepared-term, line-coefficient, point-group, or packed-partial buffers.

The resident plan now derives the PCS topology once and uses its exact counts
for every quotient slot. The plan retains the topology identity, complete
proof-program identity, and protocol identity. Its regression gate locks all
four cardinalities above.

## Multi-arena sources

The four committed trees have independent allocations and lifetimes:

```text
preprocessed LDE words  1,086,201,056
main LDE words          3,501,451,808
interaction LDE words   2,712,569,984
composition LDE words     134,217,728
```

Treating them as one synthetic base allocation is invalid. The new addressed
source descriptor carries one authenticated device address, physical stride,
and logical log size per source column. Ingress resolves tree-relative source
identities against the live tree capabilities and uploads the exact descriptor
array. The bound topology retains the source capabilities for the proof epoch.

The addressed numerator writes directly into compact per-group coordinate
storage. Its immutable `u64` offset table is validated as 19 adjacent
intervals, each exactly `2^group_log` words. This removes the false
`group_count * maximum_group_size` layout while remaining compatible with the
existing compact quotient combine and direct quotient-to-FRI-zero alias.

An exact controller-level gate also caught that the largest partial numerator
and the final quotient domain had shared one extent field. They are now
separate: numerator launch bounds use `2^23`, while compact combination and
FRI layer zero retain `2^24`.

## Corrected resident inventory

The exact Rust-pinned SN2 plan now reports:

```text
slots                     108
coefficient cells   3,717,220,288
LDE cells           7,434,440,576
logical bytes      65,933,412,580
peak live bytes    58,028,559,516
allocated bytes    58,028,560,300
terminal words          2,102,610
decommit words            878,280
fits H100 80 GB              true
```

This supersedes the quotient sizing in session 17. The difference is a
correctness repair, not a memory optimization claim.

## Device evidence

The focused native quotient archive was rebuilt by replacing only the changed
numerator object in the prior authenticated development archive. The RTX 4090
smoke exercises six resident quotient paths, including independently allocated
source arenas and packed variable-height outputs:

```text
Native CUDA quotient smoke passed: six resident paths, including multi-arena
sources, match independent CPU references
```

The host aggregate test closure instantiates the tree-relative source binder
and its production `prepareNumerator` path. A full quotient controller gate
derives the exact topology again at ingress, checks it against the resident
plan identity, binds all four source trees, and enforces the four-call stage
order: term preparation, point-group finalization, addressed accumulation,
then compact combination into FRI layer zero. The complete ReleaseSafe suite
passes:

```text
stwo-zig closure: PASS
415 transitive Zig sources
```

This object-replacement smoke is a development differential. A clean,
authenticated full AOT product build is still required for proof evidence.

## Adversarial review

The review found and this increment closes:

- AIR-versus-PCS count conflation in resident quotient sizing;
- an untested multi-arena binder outside the aggregate source closure;
- uniform output writes into compact partial storage; and
- a compact/addressed descriptor type mismatch.

The review also identified trace-writer ingress as the remaining pre-proof
integrity blocker. Pointer tables must be derived and uploaded from
schedule-owned resident slices, and each prepared body must carry an identity
sealed from its admitted catalog entry and exact buffer geometry. A caller
must not be able to pair a valid catalog digest with a swapped prepared body.

## Remaining critical path

1. Seal all 57 trace-launch owners to their actual prepared bodies,
   dependencies, and pointer tables.
2. Execute the authenticated trace, interaction, constraint, transcript, OODS,
   quotient, FRI, PoW, and decommit schedules in one resident proof session.
3. Perform exactly one bounded terminal read of the 8,410,304-byte canonical
   payload.
4. Rebuild and authenticate the complete AOT product.
5. Require exact SIMD/CUDA proof bytes and acceptance by the pinned Rust CPU
   verifier before reporting proof latency or MHz.
