# ADR-0029 — Guest Poseidon2 component, statement, and artifact identity

**Status:** accepted
**Date:** 2026-08-07

## Context

ADR-0024 fixes the `stwo.p2perm.m31.v1` architectural operation and owned call
record. ADR-0025 fixes its guest relation, duplicate-preserving multiplicity,
shared subclocks, canonical M31 conversion, extension slots, and coefficient
formula. C-005 and C-006 still need one exact component registry and one public
identity before C-007 may construct a trace.

The current base protocol is closed: its statement uses the existing
`RiscVStatement`, its main and interaction claims contain 28 component slots,
and its relation draw returns the existing twelve-pair `Relations`. Changing
those types, mixing zero-valued extension slots into a base proof, or widening
the base 25-entry hot lookup container is not an extension mechanism.

The caller layout could not be guessed from the call-buffer fields alone. It
must prove the custom program tuple, CPU retirement, one register transition,
sixteen RW-memory transitions, 30-bit aligned address derivation, 32 canonical
word conversions, and one guest request. This ADR closes that C-007 layout and
event plan before any witness implementation.

ADR-0025 also requires C-006 either to bind the loader's private RW interval
partition or to define authenticated root membership as the complete
verifier-visible policy. The verifier currently receives roots, not the ELF
loader's three interval endpoints. Claiming private interval enforcement in a
proof would therefore be false.

## Decision

### Separate profile registry

The base registry and base claim types remain byte-for-byte and type-for-type
unchanged. A profile-composed view has 28 slots for `rv32im-zkvm-v1` and 30
slots for `rv32im-zkvm-poseidon2-v1`. It appends exactly:

| slot | stable kind | component name | version |
| ---: | ---: | --- | ---: |
| 28 | `0x47504331` (`GPC1`) | `stwo.riscv.guest_poseidon2_call.v1` | 1 |
| 29 | `0x47505031` (`GPP1`) | `stwo.riscv.guest_poseidon2_provider.compat-v1` | 1 |

The open numeric kind and slot types make malformed or future identities
representable and therefore rejectable. Construction dispatch validates the
complete descriptor and returns an exhaustive typed caller/provider authority;
it never switches on a name and never returns an untyped placeholder.

The extension relation remains slot 12, name
`stwo.riscv.guest_poseidon2_io`, version 1, arity 32. The extension claim view
contains the existing base claim value unchanged and the two appended values.
Main claim mixing is base slots 0 through 27, caller, provider. Interaction
mixing is base sums 0 through 27, caller sum, provider sum, then all base
interaction-column log sizes followed by all caller and provider log sizes.

### Canonical row geometry

Both components use two preprocessed columns in this order: `is_first`, then
the statement-derived contiguous-prefix `is_active`. The minimum log size is
four. For `n_guest = 0`, both descriptors remain present with `n_rows = 0`,
`log_size = 4`, sixteen physical rows, their fixed column counts, and zero
claims.

The provider is the authenticated compatibility-v1 Poseidon2 mapping:

| property | exact value |
| --- | ---: |
| preprocessed columns | 2 |
| main columns | 445 |
| interaction events | 4 |
| two-term batches | 2 |
| interaction columns | 8 |

Its main layout is the reviewed one-enabler, sixteen-input, 426-materialization,
two-mode mapping. Active guest rows fix `(enabler, io, wide) = (1, 1, 0)`.
The legacy input, narrow-output, and wide-output events retain zero numerator;
the fourth event replaces legacy `poseidon2_io` with one positive
`guest_poseidon2_io@1/emit`. Reusing 445 columns does not authorize the legacy
IO domain.

The caller has exactly 286 main columns:

| columns | count | meaning |
| --- | ---: | --- |
| 0 | 1 | committed enabler, equal to `is_active` |
| 1..4 | 4 | execution clock, PC, `rs1`, pointer predecessor clock |
| 5..8 | 4 | pointer-register value bytes, little endian |
| 9 | 1 | aligned pointer word index `w` |
| 10..13 | 4 | little-endian 8/8/8/4 decomposition of `w + 15` |
| 14..77 | 64 | sixteen input words as four bytes each |
| 78..141 | 64 | sixteen output words as four bytes each |
| 142..157 | 16 | data-word predecessor clocks |
| 158..285 | 128 | `s0`, `s1`, `nz`, `inv` for 32 canonical words |

No call index, lane address, current subclock, recomposed M31 word, or guest
tuple field is committed separately. Those values are fixed expressions of
the columns above. Padding requires every one of the 286 main values to be
zero.

For pointer bytes `b[0..4]`, direct constraints establish

```text
b0 + 2^8*b1 + 2^16*b2 + 2^24*b3 = 4*w
w + 15 = e0 + 2^8*e1 + 2^16*e2 + 2^24*e3.
```

The caller requests `range_check_8_8(e0,e1)` and
`range_check_8_8_4(e2,4*b3,e3)`. The anchored register-memory chain supplies
the pointer bytes from public u32 register boundaries; the second request then
proves `b3 < 64`. Consequently both sides of the first equality are ordinary
integers below `p`, the pointer is four-byte aligned, `w + 15 < 2^28`, and
every derived byte address `4*(w+lane)` for lanes 0 through 15 is distinct and
inside the 30-bit commitment domain. This avoids an extra 20-bit request and
preserves ADR-0025's exact 17 access-gap requests.

### Exact caller event program

The caller has 153 events in this fixed order:

1. one `program_access@1/request` for `(pc,46,0,rs1,0)`;
2. `registers_state@1/consume(pc,clock)` and
   `registers_state@1/emit(pc+4,clock+1)`;
3. pointer `memory_access` consume/emit and `range_check_20`, access ordinal 1;
4. for lanes 0 through 15, in lane order, data `memory_access` consume/emit and
   `range_check_20`, each with access ordinal 2;
5. for inputs 0 through 15 and then outputs 0 through 15, two
   `range_check_8_8` requests and one `range_check_m31` request per word;
6. the pointer-span `range_check_8_8` and `range_check_8_8_4` requests above;
7. one `guest_poseidon2_io@1/request` over input lanes then output lanes.

Sequential two-term batching produces 77 sums, the final guest event being a
single-term batch. At four M31 coordinates per secure cumulative sum, the
caller has exactly 308 interaction columns. The exact fixed-table request
vector per active caller row, in canonical table order, is:

```text
bitwise=0
range_check_20=17
range_check_8_11=0
range_check_8_8_4=1
range_check_8_8=65
range_check_m31=32.
```

The caller event plan is a fixed compile-time array with numeric schema,
version, role, access ordinal, tuple projection, event ordinal, batch ordinal,
and interaction-column offset. C-007 and C-008 must consume that authority;
they may not rebuild it from names or append into the base lookup list.

### Verifier-visible RW policy

Authenticated membership in the public initial/final RW roots is the complete
verifier-visible memory-admission policy for this statement version. Every one
of the sixteen derived caller addresses must close through `memory_access@1`
to an ordinary memory-boundary row, whose four bytes are range checked and
whose leaves are Merkle-authenticated under those roots.

The ELF loader's data/stack/IO interval partition remains an honest-execution
admission and memory-ownership check. This statement does not claim that the
verifier knows that private partition. A future product that must prove a
particular interval partition needs a new statement/component version with
public interval authority and containment constraints; a digest of private
endpoints alone would not prove membership.

### Manifest and artifact identity

The extension manifest uses an explicit little-endian, length-prefixed SHA-256
encoding. It binds at least:

- manifest format and statement-schema versions;
- machine profile wire ID and name;
- capability bit/name and ABI version;
- protocol opcode ID 46;
- Poseidon semantic digest;
- base/extension component and relation counts;
- guest relation ID, name, ABI label, version, arity, roles, challenge,
  multiplicity, and padding policy;
- active-prefix policy and minimum log size;
- both component slots, numeric kinds, names, versions, column counts, event
  and batch counts;
- the complete caller layout and event plan, plus the versioned direct-
  constraint policy fixing degree three, 16 lanes, four-byte words, the 30-bit
  address domain, 16-word span, 32 canonical conversions, four
  materializations per conversion, clock stride four, access ordinals 1/2,
  and opcode ID 46;
- the exact caller fixed-table request vector;
- provider modes and the authenticated compatibility layout digest; and
- claim, challenge, component, and interaction-column order.

The dynamic extension statement binds this manifest digest, semantic digest,
profile, ABI, statement version, active-prefix policy, `n_guest`, redundant
caller/provider/custom-retirement/frozen-buffer row counts, `n_base`, total
steps, clock-update rows, exact base and extended fixed-table source bounds,
the checked memory coefficient value, both descriptors, and the unchanged core
statement and shard geometry.

The artifact identity has its own magic and format version and binds profile,
ABI, statement version, component/relation counts, manifest digest, semantic
digest, provider compatibility-layout digest, and a canonical digest of the
complete dynamic statement. Artifact fields supplied by a prover are compared
with independently reconstructed values; they are never authority.

### Checked admission

Cold validation reconstructs `n_base` by checked summation of the unchanged
base opcode descriptors and requires

```text
n_base + n_guest = total_steps
n_guest = custom retirements
        = frozen call-buffer length
        = caller n_rows
        = provider n_rows
n_guest < p.
```

It reconstructs clock-update and memory-boundary rows from the core
infrastructure descriptors and performs checked u64 arithmetic for

```text
3*total_steps + 14*n_guest + n_clock + sum(memory rows) + 2 < p.
```

The base-profile validator and its historical
`3*total_steps+n_clock+sum(memory)+2` expression remain untouched.

For each fixed lookup domain, validation reconstructs the base request bound
from the production base opcode event plan plus program, memory-boundary, and
clock-update sources. It then requires, with checked multiplication/addition,

```text
base_source_bound[d] + q[d]*n_guest < p.
```

Missing infrastructure authority, duplicate clock-update descriptors, any
arithmetic overflow, or a value equal to or above `p` rejects before transcript
mixing.

## Performance invariants

- Base statement, claim, relation, draw, and 25-entry lookup types do not
  change.
- Manifest hashing, statement hashing, descriptor validation, and verifier
  dispatch are cold-path work and may hash or allocate at their caller's
  boundary.
- Caller/provider row loops use fixed arrays, numeric IDs, precomputed offsets,
  and disjoint output ranges. They perform no allocation, hashing, string
  lookup, sorting, aggregation, or dynamic schema discovery.
- Main/interaction cell accounting uses the exact 286/308 and 445/8 widths;
  zero-call fixed overhead is measured separately from active-row marginal
  cost.

## Required evidence

Focused ReleaseSafe and ReleaseFast tests pin the complete registry, event and
batch order, all column offsets, the manifest digest, zero-call descriptors,
claim mixing order, checked formula boundaries, fixed-table bounds, and
artifact round trip. Mutations cover profile, component kind/slot/order/name,
version, row count, log size, column count, active-prefix policy, manifest and
semantic digests, provider layout digest, statement digest, count equality,
coefficient equality/overflow, and bound exactly at `p`.

## Consequences

C-007 now has a closed, non-placeholder caller layout and can generate directly
into final columns. C-008 has exact interaction allocation and table-counter
demand. The authenticated 445-column provider remains intentionally expensive;
any optimized provider requires a separate measured version. The proof states
RW-root membership, not unverifiable private ELF interval membership.
