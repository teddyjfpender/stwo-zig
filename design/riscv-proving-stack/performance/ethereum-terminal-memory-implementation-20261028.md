# Fresh-execution terminal-memory implementation plan

Status: concrete design with isolated terminal and initialization prototypes;
no new proof protocol is integrated or qualified. Existing v5/v6 is unchanged. This
follows the [statement source audit](ethereum-terminal-statement-source-audit-20261028.md).

## Pre-code problem match: isolated terminal algebra

Task and semantics: constrain exactly thirteen read-only word transitions after
the last guest clock, reproducing 43 public bytes plus halt/length. Inputs are
an independently admitted u64 final cycle, aligned ELF ABI addresses, 43 result
bytes, and the final word's one private high byte. The computation is a fixed
size arithmetic constraint system over M31/QM31, not a memory-state verifier.

The exact match is a public finite transition schedule feeding the existing
LogUp multiset bus. Logarithmic-derivative lookup arguments match the bus
construction ([original paper](https://eprint.iacr.org/2022/1530)); the terminal
schedule and byte decomposition below are derived specifically for this ABI.
This transfers no third-party code. An alternate final-state Merkle opening
could expose the same outputs but retains the machine-image obligation; a host
receipt omits the proof obligation and is rejected.

The selected implementation derives fixed rows only after checked host
admission, then exposes field-generic polynomial residuals, eight Boolean
high-byte limbs, typed packed transitions and an interaction recurrence. It
does not emit an accepted proof or alter an existing protocol. Its work/storage
is O(13); this predicts no end-to-end multiplier. Falsifiers are any mutated
address/clock/public byte that satisfies the equations, a valid high-byte value
that fails, or an inactive row contributing demand. Tests compare all thirteen
tuples to the independent host schedule and corrupt every tuple coordinate,
public field, bit and interaction claim. Full AIR/component/key integration,
source closure and a real detached root remain explicitly unimplemented.

Prototype validation: `block_v7_terminal_test_root.zig` passes six focused
ReleaseSafe tests. They cover all 256 high-byte values across all sixteen rows,
every single witness-column mutation, every public-output byte, ABI/clock
identity mutations, u64 limits, invalid addresses and the exact thirteen-read
cyclic interaction sum. Semantic compilation and `zig fmt` also pass. This is
equation-level qualification only, not a STARK proof or a complete memory root.

## ELF/program-data audit

The current Ethereum linker maps `.text` into TEXT but `.rodata`, `.data` and
`.bss` into DATA (`ethereum/linker.ld:19-38`). Constants read as data therefore
belong in fixed ELF RAM initialization, not the decoded instruction table.
The loader loads all PT_LOAD bytes/zero-fill before constructing the separate
declared text and RW ranges (`runner/elf_loader.zig:141-202`). Sparse memory
itself permits reads throughout the address space; the v5 initial-source
receiver explicitly rejects `layout.isProgramAddr` as a RAM first touch and
requires all other RAM addresses to lie in the RW union
(`block_v5_initial_source_receiver_v1.zig:139-149`).

Thus v7 can initially preserve the current proof product's text-as-RAM
restriction while supporting ELF constants in DATA. It must not claim to
support arbitrary RISC-V programs that load from text under that policy.
Supporting text reads later needs an independently fixed immutable-text class
and an every-access no-write constraint, because ROM fetch authority uses the
admitted static program rather than dynamically updated code. The current
memory snapshot reports program words with identical initial/final values and
clock zero (`runner/memory_state.zig:335-349`); that host representation is not a
proof that no program write occurred. The interval policy must enforce its own
restriction, including all precompile accesses. Existing v6 is unchanged.

## Clock units and the terminal suffix

`access_clock.zig:1-40` defines three access slots per architectural instruction,
in a four-wide bucket: `4*(cycle-1)+ordinal+1`, ordinal 0, 1 or 2. Slot zero
modulo four is invalid. `air/block/memory_event.zig:41-70` checks alignment,
slot validity and exact conversion from leaf-local u32 clocks to global u64
clocks. `block_execution_integer_bridge_v2.zig:15-22` independently derives the
base `4*(global_first_cycle-1)` from the admitted segment frame. The shared
integer AIR proves the bytewise addition with a zero outgoing carry; global
clocks are not reduced to an M31 scalar.

Let `C` be the admitted final architectural instruction clock (not the number
of memory rows). All guest/native/precompile access suppliers must remain bound
to their exact source frames, whose union ends at `C`. Their maximum memory
clock is `4*C-1`.

For terminal read index `i` in `0..13`, use the proposed public schedule:

```
t(i) = 4*(C + floor(i/3)) + (i mod 3) + 1
t(0) = 4*C + 1
t(12) = 4*C + 17
```

Require `C >= 1` and checked `4*C+17 <= maxInt(u64)`, equivalently
`C <= 2^62-5`. These are five synthetic memory buckets, **not five guest
instructions**. Keep execution's span ending at `C`; the independently typed
terminal source alone owns these thirteen later events. Do not route them
through `Frame.globalClock` as if the guest executed more instructions. Their
u64 clocks already satisfy `Event.validate`, so the existing sorter/packed RAM
representations can carry them unchanged. Distinct addresses make exact
inter-read chronological order immaterial to memory semantics, but the fixed
schedule simplifies census and mutation checks.

`word_memory_v5.zig` already constrains strict integer ordering at equal
addresses using four range16 clock limbs, four gap limbs and carry equations.
Its top carry is forced to zero. Thus no separate final-memory image is needed
to show a terminal read sees the preceding final guest value, provided the
transition relation is complete and contains no extra sources after `C`.

## Minimal new initialization authority

Pre-code match for the isolated compiler: this is exact offline interval
partitioning of an independently loaded piecewise-constant image. Sorted
boundary refinement, followed by adjacent-equal coalescing, is an exact match;
the complete canonical loader image is the value oracle. A sparse nonzero
lookup alone is a relaxation and cannot establish zero complements. The
implementation will preserve the existing loader rather than reproduce its
overlay logic. With W bounded initialized words and B layout/value boundaries,
the chosen construction is O(W log W + B log B) setup and O(log B) witness
classification; provider proof complexity remains unmeasured. Static setup is
per ELF/ABI and may be cached, while interval multiplicities remain per job.
The AIR helper maps interval membership to exact bounded integer differences
plus the existing multiset lookup relation, as specified below. Its test oracle
is direct loaded-memory comparison at boundaries and interior words; malicious
missing/false-zero intervals and modular gaps must fail. No provider proof is
claimed by the host compiler or constraint helper.

An important simplification applies only to the new existential-input policy:
the contents of the bounded input interval need not have their own value table.
Each address's unique first-touch value can be an arbitrary ranged u32, committed
in the sorted RAM trace. Together those values define one possible initial
input buffer; unaccessed bytes can be completed arbitrarily. Strict same-address
history prevents changing that input between reads. The guest parses the input
and proves the independently selected Ethereum result. This retains the result
claim while deliberately discarding the old exact-input-file hash claim.

This does not license arbitrary initial RAM. Derive a complete interval table
from the pinned ELF, loader semantics, admitted ABI and private-input region.
Use word addresses `0..2^30`, with disjoint half-open intervals covering that
whole domain. Each trusted table row has:

```
(lower, upper, allowed, private, initial_value_lo16, initial_value_hi16)
```

- Private input intervals: `allowed=1, private=1`; values are canonical zero
  placeholders and are not constraints on input data.
- ELF/static initialized words: `allowed=1, private=0`; exact initial value.
  Equal adjacent values may be coalesced without changing semantics.
- Permitted initially zero RAM: `allowed=1, private=0, value=0`.
- Invalid/ROM-as-RAM addresses: `allowed=0, private=0, value=0`.

The fixed partition must be independently derived and committed from exact ELF
bytes, including ordered PT_LOAD overlaps, BSS zeroing, input overlays and layout
limits. A prover-supplied sparse table cannot establish the zero complement.
The current canonical Ethereum linker has aligned private-input boundaries;
initial v7 admission should require this explicitly. Partial private boundary
words need byte masks and are a separate extension.

This table is program/ABI-specific and can reuse one fixed commitment across
blocks. Per-block multiplicities remain committed before relation challenges.
The initial table should not depend on witness first-touch selection: otherwise
its setup would repeat and a prover could omit initialized words.

## First-touch classification inside packed RAM

Prototype implementation now exists in `prover/block_v7_initial_intervals_v1.zig`
and `block_v7_initial_algebra_v1.zig`. The compiler requires an independently
pinned ELF SHA-256, exact profile and complete release ABI; it invokes the
existing loader after bounded PT_LOAD preflight and fallible reservation of
all touched word/page storage. It retains the existing layout's 1 GiB byte
address limit while explicitly classifying the rest of the full u32 address
domain as forbidden. The field-generic helper emits seven range16 requests and
one six-field interval request per first touch. Its address/before limbs and
gate are explicitly dependent on existing RAM constraints.

`block_v7_initial_test_root.zig` passes seven focused ReleaseSafe tests: ordered
overlapping byte loads and later BSS zero-fill; existential input overlay;
independent rejection of false-zero/class edits; every witness-column mutation;
the concrete field-wrapped gap attack; zero demand on nonfirst rows; malformed
input/ELF resource limits; and all allocation-failure cleanup paths. M31 and
QM31 equation evaluation are exercised. Test membership uses an exact table
oracle to distinguish helper obligations from the missing proved provider.
There is still no original STARK component, authenticated interval multiplicity
proof, cold recursive compiler or completed v7 receiver.

Avoid a separate wide first-touch proof. Extend each lane of the existing
sorted RAM AIR with an interval lookup witness gated by its **derived** first
touch selector:

```
g = fixed.global_first + row.active * (1 - row.same)
```

That is the same gate used by the current initial relation in
`block_v5_ram_lanes_interaction_v1.zig:113-114`. It is not a new free flag.
At each `g=1`:

1. Prove the existing byte address is aligned and derive word index `w` exactly.
2. Query the trusted interval provider for all six fields above.
3. Prove `lower <= w < upper` with bounded integer gaps.
4. Require `allowed=1`.
5. Require each `before` limb equals the table value when `private=0`.

One concrete packed range construction reuses range16 rather than adding 90
Boolean columns from the existing readonly classifier. Existing address limbs
are `a0,a1 in [0,65535]`. Introduce `l` with range16 and `a0=4*l`; then
`l<=16383` follows without modular wrap, and `w=l+16384*a1 < 2^30`.
For each interval gap use limbs `(d0,d1)` with range16 on `d0`, `d1`, and
`4*d1`, giving `d<2^30`. Constrain:

```
g * (w - lower - (dlo0 + 65536*dlo1)) = 0
g * (upper - w - 1 - (dhi0 + 65536*dhi1)) = 0
```

Trusted `0 <= lower < upper <= 2^30`, bounded `w` and bounded gaps keep each
residual strictly between `-M31_modulus` and `M31_modulus`; field equality is
integer equality. The provider's canonical Boolean fields select fixed/private
policy; do not accept unauthenticated witness class bits. Charge and close every
new range query and every first-touch interval query, including partition
boundary first touches, and absorb every physical interaction claim.

Reuse APIs as specifications/components, not as trusted shortcuts:

- `word_memory_v5.zig` and `word_memory_lanes_v1.zig`: exact order, predecessor
  value, shifted/public shard edges, range packing.
- `block_v5_readonly_input_plan_v1.zig::{deriveIntervals,findInterval}`: complete
  interval partition pattern, but its existing readonly policy is different.
- `block_v5_initial_sources_v1.zig::{validateLayout,inputWordAt}`: layout and byte
  decoding rules, not a new private-input admission implementation.
- `air/block/memory_transition.zig::Initial`: host witness-loader interface only;
  its `load` callback result is explicitly not proof authority.
- `block_rw_initial_provider_v2.zig`: existing fixed-provider/roster lifecycle
  patterns; its sparse/zero-query authorities cannot simply replace a complete
  independently derived ELF partition.

## Terminal source component

Use a small explicit component with thirteen active rows padded to its supported
trace geometry. Its schedule, addresses and public values come from the admitted
terminal policy. Emit ordinary packed transition tuples with `space=1` and
`before=after`:

- read 0: `0x00c00000`, value 1;
- read 1: `0x00c00004`, value 43;
- reads 2–11: `0x00c00008..0x00c0002c`, output bytes 0–39;
- read 12: `0x00c00030`, output bytes 40–42 and an auxiliary high byte `h`.

The last word is `o40 + 256*o41 + 65536*o42 + 16777216*h`. Constrain `h` as
8 bits, for example by a range8 lookup or eight Boolean witnesses, and emit its
two range16 value limbs. The high byte is authenticated through RAM consistency
but not equated to public padding. All other bytes are public constants; all
inactive rows have zero relation weight. The component must actually constrain
the transition emission; appending host `Event` records alone is not a proof.

Publish this tiny component in the initialization-provider proof when compatible
with the existing independent component sizing. Avoid another standalone parent
wrapper: the existing direct recursive collection can verify this original
provider alongside other children once its independent cold compiler exists.
Computing a terminal sum only in the host receiver is not sufficient, especially
because the final high byte is a private witness.

## Relation closure and removed work

Pre-code integrated-prototype contract: every shard commits its original fixed
and main columns once, followed by fixed/main commitments for the complete
initialization interval provider, full range16 provider and terminal component.
The independently reconstructed ordered roster, ELF/terminal/public-source
statement, security configuration and all these roots seed a new v7 transcript.
Only then draw transition, link, interval and range challenges. Each original
proof absorbs **every** physical interaction sum before its interaction root.
No v5/v6 seed, AIR/key identity or old source receipt authorizes this statement.

Reuse the original two-lane ordering equations and the common generic PCS and
quotient adapters. The new RAM interaction has transition/link/interval planes,
17 original range planes, seven additional initialization range planes, and
two census planes: 29 physical sums. Old initial-image and endpoint-image
planes are absent only from this new component. The receiver closes all 29
planes through their appropriate providers/count checks and requires the exact
contiguous shard roster. First proof qualification is scoped to an independently
pinned public list of guest transitions plus genuinely proved terminal reads;
it is not a proof of guest execution. Replacing that list with actual verified
native/caller demand requires a subsequent new-protocol integration.

The new protocol retains exact native/caller transition demand, RAM link closure,
range providers, ROM fetches and register custody. Its memory transition balance
becomes:

```
native RAM + caller/precompile RAM + terminal reads - sorted RAM = 0
sorted RAM event count = native count + caller count + 13
first-touch interval requests - trusted interval provider = 0
range requests - range providers = 0
RAM partition links = 0
```

Initialization is proved locally at every first touch. There is no initial or
final machine-RAM Merkle root in this statement and no endpoint/source PAGE
RAW/FOLD provider. Per-address final values remain part of the RAM trace but
need not be exported for all scratch addresses. Remove endpoint interaction
planes/counters only in the separately versioned v7 RAM proof; keep first/last
partition endpoints required by ordering and link constraints. Do not leave
unused claimed sums accepted without a closure owner.

## Before proof integration

The semantics above are sufficiently defined for focused AIR prototypes, but
complete integration still needs these concrete decisions and proofs:

1. Canonical executable/profile/initial-state descriptor and rejection of an
   arbitrary resumed state; public payload result/chain/schema selection.
2. Measure the independently derived interval table on the actual large ELF
   and qualify the complete guest against the explicit text-as-RAM restriction;
   the small fixture already preserves ordered loader/BSS semantics.
3. A new shared relation schedule and exact child roster; determine whether
   interval provider and terminal component share one original PCS proof.
4. Exact initial register and final completion bindings retained from v6; no
   guest write of a halt flag may bypass admitted control-flow/completion checks.
5. Cold independent key setup and detached acceptance for new components. Old
   v6 identities, keys and bundles must never accept the new statement.

Start with the two-segment fixture described in the source audit. Include
malicious interval omission, wrong class, field-wrapped gaps, clock overflow,
fake post-termination writes, duplicate terminal rows, wrong final high-byte
handling, and first touches straddling RAM partitions. The terminal plan must
accept distinct valid high bytes while keeping all 43 public bytes fixed.
Only then measure real Ethereum input with matching payload/security against
v6. This is an architectural removal of obligations, not a measured speedup.

The production statement must also retain independently ELF-derived initial PC/SP/GP and all 32 register values through mode-1 register-window admission. Replacing initial RAM/PAGE authority does not discharge initial register authority; this scoped public-transition prototype deliberately makes no execution claim.

### Integrated v7 original-proof prototype (scoped original-proof gate passed)

The isolated `block_v7_memory_bundle_v1.zig` now assembles four original proof families: packed RAM shards, a complete independently derived ELF interval table, the complete 65,536-entry range16 table, and a 13-read terminal component. It uses a dedicated `B7MB/B7MR` transcript namespace. Every fixed/main commitment appears in the ordered roster before lookup challenges. Every physical per-component interaction sum is then absorbed before the interaction commitment. The verifier derives the interval table again from the expected ELF bytes/hash/profile, reconstructs terminal fixed columns from the expected 43-byte output and ELF ABI, validates the exact contiguous RAM shard sequence, runs the original PCS verifier on every proof, and closes every relation and count.

The RAM row has 24 fixed, 76 main, and 116 interaction columns. Its 137 equations retain the original two-lane order, clock, transition, and link equations, add fourteen first-touch interval equations, and add 29 physical interaction planes. It has no initial-image or final-image Merkle source relation. This is a new statement/protocol; it does not reinterpret existing v6 proofs. The auxiliary interval and range providers each prove both the lookup sum and the total multiplicity. Total RAM events are bounded so all range requests together are strictly below the M31 characteristic, preventing count wraparound.

The present public statement supplies the exact guest transition multiset independently. Thus the first genuine gate proves initialization, sorted memory consistency, and the expected terminal output against that source. It **does not prove that a RISC-V program generated those transitions**, and is not an Ethereum admission path. Production integration must replace that scoped public list with verified native and external-caller transition demands, retain ELF-derived PC/register initialization and halt/cycle continuity, and establish its recursive independent keys before publication. The prototype currently retains all small-shard first rounds in memory; bounded streaming and production-scale memory accounting remain separate integration work. No throughput or Ethereum proving-time improvement is claimed from this local correctness gate.


The focused ReleaseSafe gate passed **3/3** on 2026-10-28:

```sh
python3 scripts/zig_protocol_test.py src/frontends/riscv/block_v7_memory_bundle_test_root.zig -OReleaseSafe -fstrip --test-filter 'v7 memory original'
```

The positive fixture contains five RAM shards, including a same-address chain split between shards, a nonzero ELF-initialized word, a writable private-input word, and thirteen terminal reads with an unconstrained-but-correct `0xa5` high byte. All eight original STARKs are serialized and deserialized, their original objects destroyed, and a fresh verifier independently rebuilds the policy and fixed providers. The negative cases reject a changed physical sum, changed public output, aliased terminal ABI, reordered shards, an excessive shard roster, noncanonical/out-of-execution source clocks, and an attempted false ELF initial value. The false initial value reaches the real original-STARK prover and fails with `ConstraintsNotSatisfied`; it is not rejected merely by a host equality check. This diagnostic uses eight FRI queries and zero PoW bits and is **not** canonical-security, execution, recursion, or publication qualification.

Compared with the original packed RAM row's 170 cells, this row uses 216 (+27%). The intended benefit is eliminating original initial/final machine-memory image proof families, not making each sorted-RAM row cheaper. That tradeoff needs real execution source integration and end-to-end measurements before any claimed speedup.

### Authenticated execution-source integration brief

The next transfer is a new transcript and admission adapter around the existing partitioned native and caller AIRs, rather than a second instruction or precompile implementation. The canonical problem remains multiset equality between independently constrained producers and sorted RAM, coupled to a sequential state machine. Every original native/caller/ROM/table and v7-memory first root must be committed before challenges. The new epoch draws the existing Universal47 and word5 schema, then a separately tagged interval relation. The unused old initial/endpoint challenge coordinates remain in the compatible word carrier but create no v7 root/image authority. No old `SourceSeal` is fabricated.

The new native adapter must derive its complete partition/access geometry from the original statement, retain exact mode-1 register windows, reuse original semantic/clock/projection/access equations, absorb all physical claims, and run the original PCS verifier. A separate admission layer binds ELF-derived initial PC/SP/GP/32 registers, segment PC/register continuity and final cycle, the complete ELF ROM, explicit terminal ABI/output, and the bounded private-input policy. Source public I/O compensation is empty here: the new terminal component and interval table supply those obligations. Every register window closes independently, never by pooling residuals across segments.

The integration falsifier is a real two-segment RV32 proof whose native program and range requests close against genuine providers and whose RAM demands close against the v7 bundle without a public transition list. Mutating a source root, state boundary, first register or physical claim must fail fresh verification. Real SHA/Keccak callers follow only after this ordinary path qualifies. Until those joins pass, epoch/source objects are open proof metadata, not accepted execution or Ethereum receipts.

### Authenticated execution integration boundary

The new `block_v7_execution_receiver_v1` accepts original native, ROM, lookup,
RAM, interval, range16 and terminal proofs together. Its trusted input is the
ELF bytes and expected digest/profile, the 43-byte terminal statement and exact
security configuration. It independently reloads the ELF, derives the complete
initialization partition, initial PC/SP/GP/registers, and decoded program ROM.
It checks the whole epoch roster before drawing challenges, verifies every
original proof freshly, checks each native state/register/ordinary-memory
residual, and closes ROM, six lookup kinds, transition and natural event counts.
No claimed transition list or old machine-memory root is admission authority.
Caller families and external retirements are rejected until their v7 source
adapters are integrated. Native local-zero/empty geometry remains rejected.

The integration fixture executes seven real RV32 instructions in two segments:
three stores set the success output byte, the 43-byte length and the halt flag.
The resulting three ordinary memory events plus thirteen terminal reads occupy
three independently proved sorted-RAM shards. The complete program table also
includes the nonfinal segment's unretired boundary fetch. Proofs are serialized,
decoded and freshly verified. This fixture is diagnostic q8/PoW0; it is neither
canonical-security nor recursive/Ethereum publication qualification.

The small fixture holds two native and all memory first rounds concurrently.
Production must replace that ownership with durable bounded first-round
checkpoint handoff before scaling execution. This does not permit rebuilding
wide commitments or drawing challenges before all source roots are committed.
The existing typed retained-PCS codec is the intended transport; global source
metadata, snapshot identities and all resource limits must remain independently
checked. The fixture establishes an admission seam, not a production memory or
throughput bound.

The authentic execution gate passed on 2026-10-28: `block_v7_execution_source_test_root.zig`
with filter `v7 authentic`, ReleaseSafe, all 10 discovered tests passed. The
fixture produced and freshly verified **10 original STARK proofs**: two native
sources, three RAM shards, ROM, global lookup, interval, range16 and terminal.
Output: `segments=2 cycles=7 ram_events=3 original_proofs=10
source_closure=verified recursion=unqualified security=q8_pow0`. Negative cases
reject a different 43-byte output, reversed native roster, changed ELF-derived
initial SP and a modified physical claim. This is genuine instruction execution
closure, unlike the earlier public-transition multiset prototype. It remains a
small RV32 fixture with no external precompile calls, no recursive parent and
no canonical-security or Ethereum block qualification. The machine-local log
is diagnostic evidence only; the reproducible gate lives in the repository.

### Epoch-v2 source closure and durable replay qualification

On 2026-10-29 the final original-source gate passed **13/13 ReleaseSafe tests**:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_execution_source_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 authentic'
```

The new caller fixture executes twelve actual instructions across two segments,
including one SHA-256 compression and one Keccak-f invocation. Its **77 guest
RAM events** comprise 24 SHA events, 50 Keccak events and three native stores;
thirteen terminal reads are added by the statement. Ten original STARK proofs
close native and caller state/register windows, the complete ELF-derived ROM,
six global lookup relations, sorted RAM, interval initialization, range16 and
the public terminal statement. The receiver rejects missing callers and caller
proofs reassigned to another native window. Original proofs are serialized and
decoded before independent verification. Epoch version 2 also reserves the
exclusive joint-memory mode; this gate exercises the separate-memory oracle.
The receiver does not accept joint-memory proofs until that adapter is qualified.

The same gate proves durable native handoff with and without ordinary RAM:

| First segment | Raw witness file | Retained native PCS | Retained access | Total storage | Codec-owned live storage after load |
|---|---:|---:|---:|---:|---:|
| One ordinary store | 2,200 B | 2,852 B | 3,088 B | 8,140 B | 15,568 B |
| No ordinary RAM | 1,200 B | 1,812 B | 0 B | 3,012 B | 4,104 B |

These are exact fixture accounting quantities, not peak process memory or
performance projections. Native owner reconstruction and subsequent prover
scratch are outside the codec-owned column. `block_v7_native_checkpoint_v1`
uses the existing structural/raw-column/PCS codecs as untrusted storage only;
it never creates an old seal or old verification receipt. Global counters change
only after successful publication. Exceeding the aggregate storage budget
leaves no files, streamed events or changes to those counters. `proveOne` restores
one segment, generates its interactions under the completed epoch and releases
all restored columns, access witnesses and PCS leases before returning the proof.
The test destroys the original owner before restoration, checks byte-identical
proofs and deletes all cache files before full fresh receiver verification.

This is still **q8 / PoW0 original-proof qualification**, not a recursive root,
canonical-security benchmark, production Ethereum block or complete streaming
memory implementation. The current memory-stage oracle retains its first rounds;
the caller arithmetic/relation bases also still contain duplicated work. The
joint-memory provider and caller relation-basis reduction address those next.

### Joint-memory whole-execution milestone

The same command subsequently passed **14/14 tests** under Epoch v2, including
both memory representations in the actual SHA/Keccak fixture. The typed
receiver now accepts either the separate-memory oracle or the new joint-memory
proof, and rejects any mismatch between the proof tag and the epoch's exclusive
family roster. Both prove the same twelve-instruction, two-segment execution,
77 guest memory events and 43-byte terminal output. Joint memory reduces this
complete original-proof roster from **10 to 6**: two native proofs, one joint
caller, one decoded-ROM provider, one global lookup provider and one heterogeneous
memory proof. This count reduction is measured by the genuine proof fixture;
it is not an end-to-end speedup claim. Recursive publication and canonical
security remain separate qualification gates.

### First-halt completion refinement (Epoch v3)

Terminal halt=1 alone establishes a successful execution prefix, not the first
halt boundary. The native completion record is not sufficient evidence that no
previous instruction already set the flag. The pinned stateless guest writes its
halt flag and then loops (`guest_runtime/ethereum/src/main.rs:197–198`), but that
source suffix is not a replacement for a constraint on arbitrary admitted ELF
programs or an instruction-level theorem about the compiled guest.

The new RAM AIR enforces this directly without a new lookup namespace. Every
active RAM event at the independently selected halt address whose *after* word
is nonzero must have clock `4*C-3`, `4*C-2`, `4*C-1`, or `4*C+1`, where C is the
admitted final guest cycle. These are the final instruction's three memory slots
and the exact terminal halt-read slot. Independently derived initialization must
fix the halt cell to zero; private, forbidden or initially nonzero halt cells are
rejected. Original strict clock/address ordering, transition closure, range16
checks and exact terminal reads remain in force. Thus an earlier write of any
nonzero value cannot be hidden by a later zero write or final successful output.

Each packed lane adds six columns: exact address equality with an inverse
witness, exact after-word nonzero with an inverse witness, and two Boolean clock
selection bits. For two bounded 16-bit address differences, their square sum
vanishes iff both vanish because -1 is nonsquare in M31. The bounded after-word
limb sum is less than M31's modulus, so it vanishes iff the whole word is zero.
The selected clock is bilinear in the selection bits and its gate is exactly
`address_match * after_nonzero`; adding another active multiplier would wrongly
raise the degree. A degree-semiring regression checks that the equations have
maximum degree four. RAM expands from 76 to 88 main columns and from 137 to 161
constraints, while keeping the same 29 physical LogUp planes and degree bound.
The recursive kernel receives the halt address and four clocks as 18 symbolic
public inputs (84 total), rather than embedding request-specific constants in
its fixed key. Epoch v3 and joint-memory protocol/layout v2 distinguish the new
AIR from historical recordings.

Focused tests include inverse/selector forgery, early `1 -> 0 -> 1`, high-limb
values, wrong clock limbs and padding. The actual execution regression runs a
real RV32 program with early halt followed by additional instructions and correct
final output; witness generation deliberately accepts that trace and the original
RAM STARK must reject it. Final positive and negative runtime results are recorded
separately after the complete source gate finishes; older Epoch v2 counts above
are historical and are not relabeled as v3 qualification.

First-halt validation completed on the final Epoch v3 source:

- `block_v7_halt_test_root.zig`: **44 passed**, including exact selector/zero-test
  attacks, maximum degree four, and independently fixed initial-halt policy.
- `block_v7_memory_bundle_test_root.zig`: **67 passed**, including multi-shard
  original proof/codec/fresh verification and early-halt rejection by the AIR.
- `block_v7_execution_source_test_root.zig`: **467 passed, 1 unrelated
  sparse-Merkle autoresearch test skipped, 0 failed**. Actual SHA+Keccak closes
  in both separate (10 proofs) and joint-memory (6 proofs) forms. Both two-segment
  base cases retain exact checkpoint proof-byte parity after cache deletion.
  The actual RV32 trace that sets halt at instruction 3 and continues through
  instruction 7 is rejected by the original RAM prover with
  `ConstraintsNotSatisfied`, even though its eventual 43-byte output is correct.

All three use `scripts/zig_protocol_test.py ROOT -OReleaseSafe -fstrip`; the
whole-source run used the shared integration build lock. These are correctness
results with q8/PoW0, not timings or recursive/canonical publication qualification.
