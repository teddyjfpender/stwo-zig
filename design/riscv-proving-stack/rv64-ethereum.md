# RV64 Ethereum milestone and next proof boundary

## Current qualification state — 2026-10-31

The historical design and acceptance gates below describe the initial software
milestone. The production control path now has constrained Keccak and secp256k1
ADD/DOUBLE services, independently sized arithmetic providers, and authenticated
RAM continuation. A fresh process verified the complete 149,306,899-instruction
round-one guest for mainnet block 24,628,607: 36 batch proofs plus a terminal
certificate, with the expected 43-byte output and final PC/registers. The producer
took 910.62 seconds and peaked at 36.06 GB RSS; the fresh receiver took 12.97
seconds and peaked at 3.44 GB. These are single isolated observations, with no
recursive aggregation. [Pinned full-block evidence](../../vectors/reports/rv64-guest-lean-20261031/complete-block-isolated-v1.json).

Guest rounds two through five are integrated. The pinned round-five ELF executes
104,253,913 instructions, and its regenerated ABI configuration produced 25 native
jobs and a fresh verified 65,536-step pilot. A complete round-five block proof and
its timing remain outstanding. The round-one timing must not be attributed to
this newer ELF. [Round-five integration](../../vectors/reports/rv64-guest-lean-20261031/round5/proving-integration-v1.json)
and [host qualification](../../vectors/reports/rv64-guest-lean-20261031/round5/mainline-integration-tests-v1.json).

The principal production cost is still the dense CPU representation: 385 main
and 148 interaction columns in the measured guest. CPU accounts for 89.67% of
main-plus-interaction cells across the round-one block. Composition, interaction
generation and commitment preparation all scale with that representation;
reducing instructions helps but does not finish the architecture work.
[Per-batch costs](../../vectors/reports/rv64-guest-lean-20261031/batch-bottlenecks-v1.json).

Two-phase shared challenges and a physically verified functional aggregate are
qualified experimental foundations, not the production Ethereum memory protocol.
They do not establish RAM closure or recursive verification. The thin Word16 CPU,
full opcode delegation, global RAM, fixed chip packing, and specialized recursion
still require their own closed proofs, adversarial tests and measured complete
costs before replacing the control path. [Functional aggregate evidence](../../vectors/reports/rv64-ethereum-20261030/distributed-functional-v1.json).

The OP/Kona port remains separate: no complete OP range proof is claimed by these
L1 block results. The production peak is still above the 16 GB target, and a
small final proof has not yet replaced the complete batch receiver.

## Initial milestone design (historical)

## Completed control execution

The software-only RV64IM/LP64 stateless-validator guest validates mainnet block
24,628,607 (66 transactions). Native execution and independent Unicorn 2.1.4
agree on exactly 835,695,366 instructions, the final PC, all 32 registers and the
43-byte host-validated output. No trace is retained and no host crypto service is
installed. [Receipts and reproduction](../../vectors/reports/rv64-ethereum-20261030/README.md).
This establishes this guest's execution compatibility. It does not establish a
block STARK, arbitrary-program refinement, full RAM equality, OP derivation or
SP1 ABI compatibility.

The ELF has RV64IM code and flags0. Rebuilding its concrete runtime avoids a
speculative A/C/CSR expansion. Single-thread atomic libcalls implement the Rust
runtime's actual 64-bit operations without an A extension. The CSP adapter keeps
its own narrow input/output contract; the Ethereum adapter independently maps a
4 MiB read-only framed input, 16 MiB stack, sparse heap and explicit halt/output.

## Work census, not a proving-time forecast

Exact PC attribution identifies a 24-round Keccak permutation leaf accounting
for 511,996,155 instructions (61.27%) and 32,835 entry-PC hits. k256/secp256k1
associated symbols account for another 181,374,875 (21.70%). Compiler memcpy
accounts for 42,251,372 (5.06%). The profile is an exclusive symbol-range census,
not an inclusive call graph. Six startup instructions have no function symbol.

This makes proving software crypto the first work to remove. Faster host
execution of the same instruction stream does not remove its witness columns,
expanded evaluations, commitments or opening work.

The existing full proof admits fewer than 2^22 steps, with 24-bit clocks. Simply
raising a limit is invalid: a full trace rounds to 2^30 rows and its current 4n
CPU composition would require log32, beyond the core's log30 circle limit.
Furthermore, four memory phases per instruction exceed the M31 modulus over
this execution; a scalar field clock cannot be extended without changing its
range/order equations. One base-field column at 2^30 rows is already 4 GiB.
No whole-block proof seconds are extrapolated from the execution receipt.

## First accelerator boundary: a Keccak permutation service

The smallest prospective change is an explicit, versioned standard ECALL in a
rebuilt guest, replacing only the audited permutation leaf. Absorb, padding and
squeeze remain software. The immutable program/ABI identity must distinguish
this service profile from RV64IM's current trapping ECALL semantics. Recognizing
an existing function PC and skipping instructions is not an admitted replacement.

An RV64 caller envelope must authenticate the service tag, 64-bit PC/pointer,
register arguments, call identity and execution clock. The provider authenticates
25 aligned 64-bit RAM cells before and after the permutation, including access
permissions and pointer/clock no-wrap conditions. Reuse existing state bits for
RAM byte values rather than committing a second byte/bit witness. Register
consistency remains local; only RAM enters the global RAM relation.

A typed call bus must prove exact coverage: omitted, duplicate, orphan and
cross-swapped calls are invalid. All provider roots/counts/descriptors are sealed
before lookup challenges, and physical claims enter the transcript. Every call,
RAM and table obligation closes. A software host permutation may generate
witness values; it is never proof authority.

The compact Keccak arithmetic is a qualified reference, not an automatic layout
choice. Its 2,204 main plus 4,164 interaction columns and paired 29-row slots
would round all measured calls to log19 and about 12.5 GiB of raw source columns,
before PCS/FFT. Existing admission stops at log18; splitting into two log18
components keeps essentially the same aggregate cells and increases verifier
work. Compare complete CPU/provider cells, masks, tables, padding, commitment
buffers, witness ownership and receiver cost for each proof batch. A narrower
unqualified design cannot be promoted on column count alone.

Providers use their own heights and share fixed tables. Compatible calls should
consolidate into components of one PCS/FRI transaction, not one wrapped proof per
call. [Cost arithmetic and mutation gates](../../vectors/reports/rv64-ethereum-20261030/accelerator-plan.json)
are the next implementation's acceptance contract.

## Long execution: an explicit protocol decision remains

Even ideal removal of the measured Keccak leaf leaves 323,699,211 software
instructions before replacement overhead. Further secp work and long-execution
support remain necessary. Existing successful-only recovery cannot replace
Ethereum's invalid-input behavior; preserve a proved rejection/status path or
explicit software fallback. Packed SHA source is not yet production-qualified.

Choose proof geometry after measuring the accelerated guest and provider call
census. Fixed 256-step windows are not the default. A batch must satisfy a joint
CPU/RAM/provider memory and opening budget, while provider sizes remain independent.
Wide witnesses are constructed once; ownership is transferred once; any retained
metadata must preserve its authenticated global obligation.

For multiple durable proofs, CPU adjacency alone is insufficient. Public
boundaries must connect registers/PC, instruction interval, immutable program and
ABI identity, RAM state, initial input and terminal output. An authenticated RAM
root/multiproof boundary is one possible contract; its page/cell hashing and
update cost must be measured before adoption. Repeating a whole RAM snapshot or
large statement for every batch is not an acceptable substitute.

A global LogUp closure is another possible design only with an explicit challenge
and commitment protocol. Independently randomized child LogUp claims cannot just
be summed afterward. A two-phase shared-challenge design must account for all
retained polynomial data; retaining hundreds of wide coefficient matrices can
exhaust disk as well as RAM. A late-closure certificate must prove the binding of
its narrow retained relation metadata rather than trust a released witness.
These are unsolved design obligations, not implemented capabilities.

Immutable setup is cached by independently derived program/ABI/geometry/provider
policy identity, while each request's statement and transcript remain separate.
The final receiver derives authority independently. Consolidate compatible
families before specialized recursion; a small root file does not establish cheap
verification or remove checkpoint/key reconstruction costs.

## Next acceptance gates

1. Implement and qualify the Keccak service boundary on small programs: exact
   output, source identity, pointer/permission/clock adversarial cases, call-bus
   coverage, table closure, and fresh receiver verification.
2. Run this identical real-block input with that service and preserve its exact
   43-byte output. Measure residual CPU instructions, permutation calls, complete
   component geometry and peak lifetime; do not call an execution-only run a proof.
3. Select and qualify the long-execution/RAM continuation contract, then prove a
   real block with independently expected initial and terminal authority. Complete
   receiver cost, immutable setup reconstruction and recursion must be included.

The OP/Kona range guest is a separate runtime/public-statement port. Its five
BootInfo fields, authenticated preimages/blob data and L1 anchor are not this
L1 validator's 43-byte output. Retained RPC roots without a complete range witness
or successful upstream guest execution are not qualification evidence.

## Architecture review: working direction

This is a proposed architecture, not an implemented proving capability.

### Measure cells, not instruction or circuit row counts

The current CPU mapping is one retirement per CPU row, followed by power-of-two
padding. Provider rows and fixed tables are additional, independently sized work.
The Keccak leaf's 15,593 instructions per entry compare with 14.5 amortized rows
in the existing paired provider: roughly 1,075 times fewer rows, but the provider
rows contain 6,399 fixed/main/interaction columns. That row ratio is not a proof
speedup. At the measured call count, the existing provider alone has about
12.5 GiB of padded source data, before commitments and FFT buffers.

In that provider, 4,164 interaction columns exceed the 2,204 main columns. Reducing
main width alone misses most committed columns. Larger lookup batches are a
candidate, but moving from two denominators to three raises the constraint degree
and may enlarge quotient/evaluation work. Record those costs and opening masks
alongside the cell reduction; do not treat the saved columns as free speed.

### Keep common CPU work lean

The actual opcode census contains 6,264 DIVU and six REMU instructions out of
835,695,366 retirements. Current `operations.zig` and `Plan.fromOpcodes` enable
division words/carries whenever division belongs to the admitted opcode union.
An independently sized division component could remove that persistent width,
but must add its authenticated operand/result relation and all provider costs.
MUL/MULHU are much more frequent (33,665,726 combined); decide their placement
from the post-crypto census rather than treating all expensive instructions alike.

Use concrete execution/arithmetic components and one shared polynomial authority
per family. Do not create a generic machine/DSL framework or a provider per tiny
operation. Keep common ALU operations inline unless the complete cost model
justifies moving them. Byte versus 16-bit limbs is likewise a measured layout
choice: smaller witnesses can add lookup tables, interaction cells and openings.

Register consistency must close within the execution batch. The present state
argument still has three register slots and one RAM slot in a shared 36-column
interaction layout; 24 inverse-coordinate columns serve register slots. It does
not materialize a separate global register-memory table. Thus the old RV32
83.8% event statistic is not an RV64 savings estimate. Expose a RAM-only external
interface for crypto providers without introducing a full 32-register-file copy
per CPU row or assuming that a second sorted register trace is cheaper.

### Prefer architectural state boundaries and batch-local clocks

Working direction: large, memory-budgeted execution batches linked by authenticated
RAM roots, registers and PC. A root commits architectural RAM values and mapping
policy; proof-only last-access clocks need not be part of the carried machine
state. Each batch can close its own register/RAM relations with local timestamps,
then prove that its final architectural state is the next batch's initial state.
This avoids both the whole-block scalar-clock overflow and adding wide global
clock columns to every access. Global instruction intervals remain explicitly
bound and checked for coverage/adjacency.

The RAM-root provider must batch openings and net updates by touched page/cell,
not prove a separate Merkle path on every load/store. Its actual hashing,
initialization, opening and padding costs are an acceptance gate. Authenticate
immutable ELF/data, zero initialization and initial input once; bind final output
and halt to the terminal state. A producer-selected initial RAM root is not
independent authority. Do not repeat the entire input or RAM snapshot per batch.

This choice permits each durable batch proof to close independently. It avoids
the unresolved idea of adding independently randomized LogUp claims after the
fact. Root linkage is not free: measure the complete RAM commitment provider and
compare it with any explicit shared-challenge alternative before implementation.

Choose a batch from the joint CPU, RAM and crypto live-memory budget; keep each
component's height independent. Cut only at completed architectural instructions,
so an atomic crypto service's RAM transition does not straddle two batches.
Use one PCS/FRI transaction per batch and shared providers/tables across all calls.
Construct/adopt witnesses once, retire them only after obligations are certified,
and cache independently derived immutable setup separately from request identity.

Consolidate compatible batches before specialized aggregation. The receiver
must enforce identical program/ABI and block context, complete instruction
interval coverage, CPU/RAM adjacency, initialization and terminal output. No
one-proof-per-call wrapping and no assumption that a small final proof means
cheap verification. Keep receiver time, key reconstruction and checkpoint bytes
inside the performance acceptance budget.

### Implementation order

1. Qualify a small RV64 Keccak service plus authenticated RAM/call envelope,
   keeping the software guest as control; compare candidate provider layouts.
2. Re-run the same real block to measure residual CPU and provider work, then
   qualify secp recovery with complete valid/invalid-input behavior.
3. Prototype the rare-division split and batched RAM-root transition separately;
   require whole-system cell, memory and verification wins before promotion.
4. Select batch geometry from those measurements, then implement durable state
   continuation and aggregation with explicit receiver coverage checks.

Even subtracting the measured Keccak leaf and k256 symbol group would leave
142,324,336 retirements before replacement overhead. This is an illustrative
lower-work scenario, not a forecast or proof construction. Crypto acceleration
is necessary; lean CPU representation and scalable state continuity are also
required.
