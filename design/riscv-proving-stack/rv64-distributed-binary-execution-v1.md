# Experimental register-only BINARY execution aggregate

This profile proves a finite execution interval of actual RV64 AND/OR/XOR
register instructions. It has two CPU shards and one shared BINARY truth worker,
with three independently verified PCS/AIR/FRI proofs. It is not a general RV64,
RAM, ELF-runtime, or Ethereum execution profile. No existing execution CLI or
root-chain receiver selects it.

The immutable ROM independently decodes the expected raw words and full64 PCs.
Its tuple authenticates PC4/NEXT4 as four u16 limbs each, opcode, all three register
IDs, and their zero flags. NEXT uses wrapping u64 increment in that immutable
construction. The CPU has44 main columns,56 interaction columns, and61 local
residuals. It emits one FUNCTION13 request per active instruction and keeps
register, ROM, U16 and U8 relations local to its own proof. There are no65 opcode
selectors, whole-register snapshots per CPU row, or duplicated Byte20 state
headers. This small profile supports exactly three register-only instructions;
its width must not be represented as a qualified replacement for the full ISA.

Each local CPU proof also contains its own immutable ROM provider, a32-row
register endpoint component, and independently sized U16/U8 range providers.
The BINARY worker uses the qualified42-main/28-interaction authority and canonical
byte-AND provider. Total physical roster:5+5+2 =12 components. Public statements
are coefficients mixed into the transcript; fixed setup depends on immutable
program and geometry, never request values or counts beyond geometry selection.

## Complete commitment and receiver contract

All tuple and multiplicity columns of all three workers commit before any
shared FUNCTION challenge is derived. Workers export actual fixed/main PCS
roots. The complete ordered Manifest binds those roots, exact schemas,
geometries, request/program/job identities, opcode map, relation epoch and mass
limits. Every worker checks its own retained roots and transcript against the
Manifest. No accepting API takes a supplied alpha. Local REG/ROM/range/AND
challenges are separately scoped to each proof's roots and Manifest transcript.

Physical claims enter their own transcript before interaction commitments and
constraint coefficients. A CPU's open verifier returns only FUNCTION debt after
its real AIR/FRI proof and all local REG/ROM/U16/U8 closures pass. The BINARY open
verifier similarly closes AND locally and returns only its verified FUNCTION
debt. Aggregate acceptance sums exactly those three returned FUNCTION debts and
requires zero. Local REG, ROM or range debts cannot cancel across shards.

Receiver-owned `Expected` pins program identity, request and instance identities,
geometry caps, exact total steps, genesis PC/all32 register values, terminal
PC/all32 expected register values, and the three work IDs. Intermediate snapshots
are advice, not independent authority: the receiver checks exact coverage,
PC/value adjacency, physical leaf proofs, and the shared lookup closure.

## Explicit local-clock reset and canonical values

The version is **reset-v1**. Each CPU's initial register clocks are physically
zero in the endpoint component. Final clocks are public coefficients bounded by
4*steps and proved by local REG closure. Across shards only PC and all32 register
VALUES continue. A previous shard's final clocks are never equated to the next
shard's initial zeros. The reset policy is explicitly hashed into the execution
context and public CPU statement domain.

The canonicality argument uses physical multiset closure, not native journal
checks:

1. Every enabled CPU register slot consumes one before state and emits one after
   state. ROM membership fixes IDs/zero flags, so enabled weights are Boolean.
   After clocks are fixed4*row+slot+1. Initial states have clock0, one per register;
   final endpoints consume one state per register. Local positive mass is bounded
   below the M31 characteristic before challenge derivation.
2. Therefore every before tuple must have support among canonical initial states
   or actual after states, except with the separately budgeted random-relation
   collision probability. There is no free negative multiplicity provider for
   register states. After timestamps are unique; unit flow cannot fork or be
   hidden by characteristic wrap.
3. Gap16 and gap8 have real U16/U8 lookup membership, so gap is in[0,2^24).
   After clocks are below2^24. A supported before clock is likewise in[0,2^24).
   Thus before+gap+1<2^25<M31, and the clock equation proves the INTEGER strict
   order before<after. This excludes dormant ghost cycles and future-before
   cycles; timestamp uniqueness alone would not suffice.
4. Registers begin with canonical u64 public values. Reads preserve their value.
   Writes receive canonical four-u16 results from the shared BINARY truth proof.
   The acyclic unit-flow state chains therefore propagate canonical values to
   reads and previous_rd, including a destination never previously read. x0 is
   separately fixed to zero and disabled in register flow.
5. Only after all three proofs and FUNCTION closure pass can the shared truth
   premise be used. A locally verified open CPU fragment is not accepted
   execution by itself.

The same argument does not authorize global RAM canonicality pruning. RAM needs
its own physically unique initialization/teardown, authenticated origins and
strict-order/coverage argument. It remains unsupported here.

## Qualification scope and transport

The native fixture executes six instructions exactly once, including source/
destination aliases, a write to x0 with a nonzero ignored result, and high64-bit
values. VM/Memory owners are destroyed before proving. The proof-producing
harness retains three worker owners in one process; no scheduler speedup or
cross-process producer fanout is claimed. The independent receiver process
constructs expected ROM/genesis/output without VM replay.

Receipt snapshots use bounded explicit LE64 fields. Only QM31 coordinate claims
use JSON, where each coordinate is at most31 bits. Geometry mismatch is rejected
before key/witness allocation. A decoded receipt is not acceptance: the receiver
still reconstructs expected descriptors, verifies each proof against actual
Manifest roots, and closes every typed claim.

q70/P26 is the per-proof configuration. This document makes no claim of96-bit
aggregate union security from three such proofs without an explicit union-bound
budget. Global RAM, wider opcode families, arbitrary mutable memory and production
Ethereum acceptance are further milestones; the qualified root-chain prover
remains the control.
