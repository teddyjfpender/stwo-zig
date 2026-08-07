# ADR-0024 — Versioned `CUSTOM-0` ABI for guest Poseidon2

**Status:** accepted
**Date:** 2026-08-06

## Context

[ADR-0003](0003-one-proof-precompiles-first.md) selects a specialized guest
Poseidon component inside the core statement and transcript before any
independent leaf proofs or recursive aggregation. The remaining C-001 decision
is the architectural boundary by which a guest requests that work.

The existing proof-bearing machine is exactly `rv32im-zkvm-v1`. Sail remains
the authority for its RV32IM instruction semantics. Its opcode protocol assigns
IDs 0 through 45, rejects `CUSTOM-0`, and treats ECALL and EBREAK as unretired
host-control events. The proof language contains successful retirements only.
Recognizing an ordinary instruction sequence, assigning proof semantics to an
ECALL, or accepting a custom word without changing the declared machine profile
would silently enlarge that base claim.

The invocation must also fit the existing state and memory composition. A full
M31 Poseidon2 permutation has sixteen input and sixteen output field elements.
The sparse RW-memory commitment is byte addressed over a 30-bit domain, and an
in-place transition can bind a word's prior and next values with one memory
state-chain edge. An out-of-place interface would require at least twice as
many data-word transitions. A variable-count descriptor would reduce guest
loop instructions but introduce variable architectural fan-out, descriptor
validation, more difficult failure atomicity, and additional indexing and
multiplicity questions before measurements show that the loop rows matter.

The existing Merkle Poseidon component is an implementation seam, not the guest
ABI. Guest calls must not balance against the Merkle relation merely because
both evaluate the same mathematical permutation. The exact guest relation
domain, version, signed roles, and multiplicity policy remain the separate
C-002 decision.

Finally, two repository examples are not semantic authorities. The constants
in `src/frontends/riscv/common/poseidon2.zig` are explicitly generated as
placeholders, and `vectors/riscv_guests/poseidon2_m31` intentionally follows an
example permutation with round constant 1234. Neither may define the new ABI's
result.

## Decision

Introduce one explicit zkVM extension profile containing one versioned
`CUSTOM-0` instruction. ABI version 1 performs exactly one full Poseidon2-M31
permutation in place. Multiple guest calls are batched only after execution, in
the prover's specialized component work.

This ADR fixes guest-visible execution and ownership semantics. It constrains,
but does not accept on behalf of C-002, the relation schema used to prove those
semantics.

### Machine profiles and semantic authority

The profiles are:

| Profile | Meaning |
| --- | --- |
| `rv32im-zkvm-v1` | Existing Sail-refined base profile. Extensions are I and M only. Every `CUSTOM-0` word remains invalid. |
| `rv32im-zkvm-poseidon2-v1` | The exact base profile plus the single instruction defined by this ADR. It is a zkVM extension, not RV32IM or Sail behavior. |

The extension capability token is
`stwo.poseidon2-m31.permute-in-place@1`. Its function is the canonical typed
program `riscv.poseidon2_m31.permute.v1`, whose v1 semantic SHA-256 is:

```text
9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed
```

This semantic digest identifies the mathematical function, not a native Zig
struct, backend executable, call-buffer layout, AIR materialization policy, or
proving schedule. The initial provider may reuse the authenticated 445-column
compatibility layout, but that physical layout is independently versioned as
specified by [ADR-0021](0021-backend-neutral-poseidon-program-identity.md).
H-010 selected no optimized replacement.

Base-profile decoding, opcode manifests, statement geometry, transcript
challenges, proof artifacts, and verification remain unchanged. The extension
manifest inherits base opcode IDs 0 through 45 and assigns protocol opcode ID
46 to this instruction only within `rv32im-zkvm-poseidon2-v1`. A decoder cache
must therefore be profile-specific or include the profile in its key.

### ELF admission note

An extension executable must contain exactly one ELF note with all of the
following properties:

| Field | Required value |
| --- | --- |
| section name | `.note.stwo.zkvm` |
| section type | `SHT_NOTE` |
| section flags | `SHF_ALLOC` clear; admission metadata is not loaded guest memory |
| section alignment | 4 |
| note name | five bytes `STWO\0` |
| note type | unsigned value 1 |
| descriptor length | 56 bytes |

The descriptor is a packed canonical byte sequence, not a native struct:

```text
offset  size  field
0       8     magic = "STWZKVM\0"
8       2     note schema version, u16 little endian = 1
10      2     machine profile ID, u16 little endian = 1
12      8     required capability bits, u64 little endian = bit 0 only
20      2     Poseidon ABI version, u16 little endian = 1
22      2     reserved, u16 little endian = 0
24      32    raw semantic SHA-256 bytes
```

Profile ID 0 is reserved for the base profile, which needs no note. Profile ID
1 means `rv32im-zkvm-poseidon2-v1`; capability bit 0 means the capability token
fixed above. All unknown capability bits, nonzero reserved bytes, wrong note or
ABI versions, an unknown profile ID, and a semantic-digest mismatch reject the
ELF before CPU initialization. Missing or duplicate notes reject an executable
selected for the extension profile. A base-profile runner rejects a note that
requests the extension rather than silently ignoring it.

The note is load-time admission metadata and is not, by itself, a proof
binding. C-006 must bind the effective machine profile, extension-manifest
digest, Poseidon semantic digest, and ABI version in statement and artifact
identity. A verifier must fail closed unless its policy admits that exact
combination. Products advertise execution, proving, and verification support
separately; Metal must report the extension unavailable until C-010 is
admitted, with no hidden CPU fallback.

### Instruction encoding

The instruction occupies the RISC-V `CUSTOM-0` major opcode and has this exact
R-type-shaped encoding:

```text
31          25 24          20 19          15 14       12 11           7 6             0
+--------------+--------------+--------------+-----------+--------------+---------------+
| funct7 = 1   | rs2 = 0      | rs1          | funct3=0  | rd = 0       | CUSTOM-0 0x0b |
+--------------+--------------+--------------+-----------+--------------+---------------+
  ABI version    reserved       state pointer  permute16   no result
```

For register index `rs1`, its 32-bit word is:

```text
0x0200_000b | (u32(rs1) << 15)
```

The guest pseudo-mnemonic is `stwo.p2perm.m31.v1 rs1`. A GNU-style assembler
wrapper may emit:

```text
.insn r 0x0b, 0, 1, x0, rs1, x0
```

Only `rs1` varies. A different `funct7`, `rs2`, `funct3`, `rd`, or major opcode
does not invoke this ABI. Values not assigned by a later accepted profile are
reserved and reject. The implementation must decode the complete word; it may
not recognize a mask broad enough to admit future versions accidentally.

### Architectural semantics

Let `ptr` be the unsigned 32-bit value read from `GPR[rs1]`. One successful
invocation performs these operations:

1. Read `ptr`; no general-purpose register is written.
2. Require `ptr` to be four-byte aligned.
3. Compute the half-open byte span `[ptr, ptr + 64)` in widened arithmetic.
   It must not wrap, must be contained wholly in one declared proof-admitted
   RW-memory interval, and must remain inside the 30-bit byte-addressed
   commitment domain. Consequently `ptr` is at most `0x3fff_ffc0`.
4. Snapshot sixteen consecutive little-endian `u32` words at
   `ptr + 4 * lane`, for lanes 0 through 15, before writing any output.
5. Require every word to be a canonical M31 representative:
   `0 <= word < 0x7fff_ffff`. The implementation must reject rather than
   reduce a noncanonical word modulo the field modulus.
6. Evaluate exactly `riscv.poseidon2_m31.permute.v1` over the sixteen field
   elements.
7. Replace the same sixteen words atomically with the sixteen canonical output
   representatives, in lane order.
8. Retire exactly once, increment the instruction clock once, and set
   `pc = pc + 4` under the existing successful-retirements-only model.

The pointer register read uses access subclock `.first`. The sixteen distinct
in-place RW-memory transitions use the same `.second` phase clock. There is no
separate architectural read edge followed by a write edge: each state-chain
transition binds its prior input word and next output word at one address. No
status value is returned. Invalid invocations are execution rejection, not
guest-visible traps or inactive trace rows.

The common `.second` phase for sixteen distinct addresses is an accepted ABI
shape but not yet an accepted AIR soundness result. C-002 must discharge the
obligations listed below before C-004 implements this behavior.

### Validation and failure atomicity

Invocation is a two-phase transaction.

The prepare phase must complete every fallible or rejecting operation:

- validate profile, complete encoding, pointer alignment, widened span, RW
  interval containment, and commitment-domain containment;
- snapshot all sixteen inputs and their previous memory clocks;
- validate canonical M31 encodings;
- snapshot the pointer register's previous access clock;
- compute all sixteen outputs in detached storage;
- reserve one call-buffer entry and one execution row;
- reserve every state-chain access-list and address-map entry;
- reserve initialized-word-map entries and materialize any sparse memory pages
  needed by the writes; and
- prepare any other ownership transfer required for an infallible commit.

Only after prepare succeeds may commit update memory, register-access history,
state chains, the execution trace, the call buffer, PC, or instruction clock.
Commit uses prepared or assume-capacity operations and must contain no allocator
call, fallible map insertion, lazy page creation, or validation branch.

On rejection or allocation failure, all architectural and proof-visible state
is unchanged: CPU registers, PC and clock, memory bytes, state-chain entries and
lengths, trace rows, and call-buffer length and entries. Capacity obtained by a
successful reserve before a later failed reserve need not be byte-for-byte
rolled back, but it must be unreachable as a call or trace entry and must not
alter any proof-visible result. Tests inject failure at each prepare allocation
site and compare the complete logical state before and after.

The implementation uses stable errors equivalent to:

- `RequiredCapabilityUnavailable`;
- `InvalidPrecompileEncoding`;
- `PrecompileAddressMisaligned`;
- `PrecompileSpanOutsideRwMemory`;
- `NonCanonicalPrecompileInput`; and
- `OutOfMemory`.

The current memory writer may allocate or panic while creating sparse pages.
It therefore cannot be called directly during commit; C-004 requires a
fallible prepared-write boundary or equivalent transaction mechanism.

### Owned call buffer

The runner, not `HostRuntime` and not a global registry, owns the call buffer.
Its mutable builder is part of execution state. On successful execution it is
transferred into `RunResult` and frozen before any prover worker observes it.
The prover borrows the frozen buffer until trace construction is complete, and
`RunResult.deinit` releases it exactly once. An unsuccessful run exposes no
partially frozen buffer.

Each logical v1 record contains at least:

```text
execution_clock              u32
pc                           u32
state_ptr                    u32
pointer_register             u5
pointer_previous_clock       u32
input[16]                    canonical u32 M31 representatives
output[16]                   canonical u32 M31 representatives
memory_previous_clocks[16]   u32
```

Records remain in successful retirement order. Repeated identical calls remain
repeated records with multiplicity one. The buffer is never sorted, deduplicated,
or aggregated. Buffer index may be reported as a diagnostic execution ordinal,
but is not a guest-visible value and is not automatically a proof-tuple field.
The empty buffer has one canonical frozen representation.

The physical buffer layout is private implementation policy. An AoS, SoA, or
bounded chunked AoSoA implementation is acceptable only if it preserves the
logical record and order. C-003 benchmarks the layouts against append cost,
column-oriented witness filling, peak memory, and allocation count; this ADR
does not make host layout part of the ABI or artifact identity. The ordinary
execution trace must not gain sixteen-input and sixteen-output arrays on every
non-precompile row.

### Proof component direction and prover batching

The invocation component is the caller/request side of a new guest relation.
It binds the committed custom instruction and its state, register, and memory
effects to a tuple containing the sixteen inputs and sixteen outputs. The
specialized Poseidon component is the provider/supply side and contributes the
opposite signed relation event after proving the exact permutation. Caller and
provider multiplicities must close globally in the same transcript.

This guest relation must be domain separated from both sparse-Merkle Poseidon
relations, including the existing `poseidon2_io` relation. The extension
components are appended without renumbering or changing the base profile's
fixed component and challenge order. The initial provider uses the reviewed
445-main-column compatibility mapping and its full input/output mode; this ADR
does not promote an H-010 candidate layout.

One ABI invocation always means one permutation. After the call buffer freezes,
the prover maps its records to one contiguous active call table and one
contiguous provider table, pads them canonically, and partitions disjoint row
ranges across the existing bounded work pool. It may construct main traces,
interaction traces, and quotients concurrently when their dependencies permit,
but scheduling never changes call order, claims, transcript order, proof
semantics, or cleanup. Components do not create nested unbounded pools.

The relation tuple does not need a call ID to prove a deterministic pure
function. An execution ordinal may remain diagnostic unless C-002 demonstrates
a protocol need. Mode and ABI version should be carried by the typed relation
domain/schema and extension identity rather than increasing the 32-element
input/output tuple, but C-002 owns that final representation.

### Compatibility and fallback

Guest support provides two explicit library entry points:

- `poseidon2_permute_in_place_v1`, which emits the custom instruction; and
- `poseidon2_permute_software_v1`, which evaluates the exact same pinned
  function with ordinary base-profile instructions.

A build or deployment system may select a base-profile software ELF after
querying product capabilities and before execution begins. An admitted
extension executable must never fall back silently at the instruction, runner,
prover, or Metal boundary. Runtime feature negotiation inside one guest is
deferred because proof semantics must not depend on an uncommitted host answer.

## C-002 soundness obligations

This ADR does not authorize relation construction until C-002 accepts a guest
relation/version ADR that resolves all of the following:

1. Define a typed guest-specific domain and `RelationSchemaId`, with an exact
   version, challenge-combination convention, 32 ordered tuple fields, caller
   and provider roles, signed numerators, padding policy, and public-boundary
   policy. It must be impossible for a guest call to cancel a Merkle event.
2. Prove that one pointer-register access at `.first` and sixteen distinct
   address transitions at one `.second` clock preserve strict per-address
   memory history, alias safety, execution reachability, and the current public
   clock contract. If this cannot be shown without changing the clock protocol,
   this ADR must be revisited before implementation rather than weakening the
   check.
3. Fix duplicate-call semantics as repeated active rows with multiplicity one,
   or provide a stronger bounded-integral alternative with equivalent omission
   and duplication negatives. Padding contributes zero.
4. Prove field/word uniqueness: input and output byte decompositions bind
   canonical representatives and cannot alias through M31 reduction.
5. Establish source-coefficient bounds for sixteen memory transitions per call,
   all range requests, duplicate calls, active and padded rows, and total call
   count so no integer multiplicity or accumulator coefficient wraps in M31.
6. Establish function uniqueness for every live provider row: the sixteen
   inputs determine all sixteen outputs under the complete fixed constants,
   selectors, materialization equalities, and output constraints.
7. Specify canonical empty-table geometry, active-row count binding, provider
   and caller row-count equality, and the extension's placement after the
   unchanged base transcript/challenge block.
8. Pin mutation tests for a changed lane, address, previous clock, output,
   relation version, role, signed multiplicity, active selector, padding cell,
   omitted call, duplicated supply, and statement count.

Until those obligations are accepted, the proposed relation name
`guest_poseidon2_io_v1` and request/supply signs are design labels, not protocol
authority.

## Performance requirements and gates

The performance hypothesis has three parts:

- one custom retirement replaces the guest's many ordinary permutation
  instructions and their core-family rows;
- in-place state replacement uses sixteen data-word transitions instead of the
  thirty-two needed by separate input and output buffers; and
- a frozen contiguous provider table exposes independent row ranges to bounded
  CPU or, after separate admission, Metal workers.

The specialized permutation still costs one wide provider row per call, plus
call-bridge and relation work. Padding, commitments, LogUp, quotient work, and
memory pressure can dominate at different call counts. This ADR therefore
makes no proving-speed, proof-size, crossover, or total-work claim.

Implementation must preserve a separate base-profile dispatch path or select
the profile once outside the hot loop. The base decoder and proof registry must
not pay per-instruction dynamic capability dispatch. The call hot path performs
no string lookup, global registry lookup, per-call timer, or unbounded thread
creation. After capacity is available, recording a call is allocation free.

C-013 admission follows [PERFORMANCE.md](../PERFORMANCE.md) and includes
verified proofs for:

- the exact native software implementation and the precompile at identical
  inputs and call counts;
- zero-call base and extension cohorts;
- pure-call, mixed-core, balanced, and dominant-precompile workloads;
- one, two, four, and maximum admitted worker counts; and
- CPU and separately authenticated Metal cohorts where supported.

Reports retain raw samples and include guest retirements, active and padded
rows, sixteen memory transitions per call, range requests, main and interaction
cells, commitment/LDE and quotient work, stage wall time and total work, task
queue/run/wait time, worker utilization, call-buffer capacity and growths, peak
RSS, and proof verification. Base-profile proof geometry and protocol bytes
must remain unchanged; a base execution regression outside its measured noise
interval blocks activation. The predeclared numerical thresholds, paired
sampling schedule, A/A admission rule, and `FAIL`/`NO_VERDICT` policy are the
normative M6 entry in
[`m5-m9-protocol-v1.json`](../performance/m5-m9-protocol-v1.json); changing
them after candidate results are visible requires a new reviewed protocol
version and a fresh capture.

Correctness and failure gates include:

- base-profile rejection of the exact custom word;
- every one-field encoding mutation and every malformed-note class;
- misalignment, 64-byte arithmetic wrap, commitment-domain overflow, RW-range
  crossing, and placement outside admitted memory;
- input words equal to `p`, `p + 1`, and `u32::max`;
- allocation failure at every prepare reservation with logical state equality;
- empty buffers, repeated identical honest calls, and large bounded call sets;
- native/precompile agreement against the exact independent typed corpus;
- forged input, output, address, prior clock, mode/version, multiplicity,
  padding, count, profile, manifest, and artifact identity; and
- CPU proof verification in a new process, with unsupported products failing
  closed.

## Consequences

- The base Sail/RV32IM statement stays honest: guest Poseidon is an explicit,
  advertised zkVM extension with separate artifact identity.
- The guest interface is small and deterministic, while the prover can batch
  and parallelize calls without exposing scheduler choices to the guest.
- In-place operation minimizes RW state-chain traffic and call descriptors.
- Successful-retirements-only behavior remains uniform: invalid calls do not
  create trap or inactive proof rows.
- Transactional preparation requires new fallible reserve and prepared-write
  machinery in the runner and sparse memory implementation.
- The extension adds statement components, a relation challenge, range work,
  artifact fields, verifier policy, and a new negative-test fleet.
- Programs using the custom instruction are deliberately not portable RV32IM
  executables; the separately built software implementation is the portable
  path.
- Existing placeholder/example Poseidon guest code must be replaced by a new
  exact corpus before semantic equivalence can be claimed.
- No production behavior changes merely by accepting this ADR. Activation
  still proceeds through C-002 through C-013 and their proof, mutation,
  artifact, backend, and performance gates.

## Rejected alternatives

- **Use ECALL or an existing hash syscall:** rejected because ECALL is an
  unretired host-control boundary in the base profile and current syscall
  execution is not proof-bearing. Reusing it would obscure whether a host
  result is constrained.
- **Recognize a native RV32IM instruction sequence:** rejected because replacing
  ordinary Sail behavior with a hidden proof shortcut changes semantics and
  creates a much harder trace-compression/refinement obligation.
- **Use a runtime entry-point address or MMIO magic range:** rejected because
  ordinary control flow or memory effects would acquire host-dependent meaning
  without an explicit instruction and profile capability.
- **Start with a variable-count descriptor batch:** rejected for v1 because it
  creates variable fan-out, descriptor aliasing, partial-failure, dynamic
  memory-geometry, ordering, and multiplicity obligations to save unmeasured
  loop rows. C-013 may justify a separately versioned ABI later.
- **Use separate input and output buffers:** rejected because the permutation is
  naturally in place and separate buffers double the minimum data-word
  transitions while adding overlap and alias cases.
- **Expose only a two-to-one register hash:** rejected because it is not the
  full permutation required by sponge and native guest workloads. It may be a
  separate future operation with its own selector and relation.
- **Reuse the Merkle `poseidon2_io` relation:** rejected because identical
  arithmetic does not make guest calls and commitment infrastructure the same
  semantic domain; cross-domain cancellation must be impossible.
- **Deduplicate identical calls or put host ordinals in the relation tuple:**
  rejected because repeated active rows already express multiplicity, while an
  ordinal adds protocol width without a demonstrated soundness need.
- **Silently execute software on an unsupported backend:** rejected because
  capability and proof semantics would become host dependent. Binary selection
  occurs before execution.
- **Adopt the placeholder or example guest permutation:** rejected because it
  does not have the canonical semantic digest and would prove the wrong
  function efficiently.
- **Select an optimized Poseidon physical layout now:** rejected because H-010
  found no reproducible candidate win and did not execute the production proof
  boundary.
- **Begin with independent core and precompile proofs:** rejected by ADR-0003
  until one-transcript call closure and relation summaries are established.

## Revisit when

Revisit this decision if C-002 cannot prove the shared memory subclock sound,
if C-013 shows core loop rows or call-buffer layout materially dominate the
verified crossover, if a descriptor batch can be specified with bounded and
atomic fan-out, if the canonical Poseidon function or field changes, if the
program commitment begins authenticating extension metadata directly, or if a
new RISC-V standardized extension supersedes this private encoding.

Any semantic change requires a new machine profile, capability token, ELF-note
ABI version, instruction encoding version, semantic identity, and verifier
admission. It must not reinterpret an already accepted v1 binary or proof.
