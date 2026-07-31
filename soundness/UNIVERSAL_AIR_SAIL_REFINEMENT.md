# Universal AIR → Sail refinement engineering plan

> **Current claim ledger:**
> [`RISCV_FRONTEND_VERIFICATION_STATUS.md`](RISCV_FRONTEND_VERIFICATION_STATUS.md)
> is the concise normative status and roadmap. References below to Team A or
> Team B describe the historical parallel rollout only; they are not semantic
> categories, publication grades, or current ownership boundaries.

**Status:** `whole_frontend_verified = false` and
`proof_system_soundness = false`. The receipt currently committed on `main`
records the earlier graded rollout; it is not the publication claim targeted
by FV-1/FV-2. The active promotion must establish a neutral 46-opcode
inventory, 46 generated-Sail normalizers, 46 accepted-production-AIR
implications, full-step retirement framing, an exact axiom audit, reproducible
receipts, and merge to `main` before those stronger results count as repository
evidence. FV-3 (Word32/M31 discipline), FV-4 (arbitrary-trace composition),
and FV-5 (independent reproduction/review) remain blocking after that landing.

**Primary result:** machine-check, for every input admitted by each of the 46
proof opcodes, that satisfaction of the shipped row AIR and its exact local
lookup obligations implements the corresponding transition of the pinned Sail
RV32IM model.

**Semantic authority:** `riscv/sail-riscv` at
`8c7f2da58de0ba5e4457e4de07e0046f0439f35f`, compiled with Sail `0.20.2`
under the profile fixed by
[`conformance/2026-07-26-riscv-sail-contract.md`](../conformance/2026-07-26-riscv-sail-contract.md).

**Composition target:** premise 5, “Universal local refinement,” of theorem
SA-1 in
[`soundness/SAIL_AIR_COMPOSITION.md`](SAIL_AIR_COMPOSITION.md).

This document is the engineering contract for the repository's main formal
semantics workstream. It is deliberately stricter than “run an SMT solver over
the current corpus.” Finite Sail agreement, committed-witness mutation tests,
and two-copy row uniqueness remain valuable evidence, but none quantifies over
every admitted architectural state. The result specified here does.

### Historical pilot baseline and active promotion

The earlier release receipt contains a kernel-checked vertical prototype for
LUI and ADDI under `formal/riscv-refinement/`. Its proved implication is:

```text
source-bound production LUI/ADDI AIR and lookups
                  +
explicit local program/register environment
                  |
                  v
generated normalized Sail retirement capsule
```

The Lean proof derives LUI's four destination bytes and ADDI's source
preservation, four-byte carry recurrence, modular 32-bit sum, x0 behavior,
decode, next PC, and emitted local tuples. It includes concrete non-vacuity
witnesses, including the ADDI overflow case
`0x7fffffff + 1 = 0x80000000`. The exported theorem set is scanned for proof
escapes and audited with `#print axioms`; only `propext`,
`Classical.choice`, and `Quot.sound` are permitted.

The generator freshly exports all 17 production symbolic-AIR families, accepts
only the exact closed LUI and base-ALU-immediate normalized schemas, packages
LUI/ADDI, and binds every RISC-V frontend source plus the generator and proof
closure by SHA-256. Independently of that Level-1 normalizer, every production
family now uses one typed `ConstraintProgram` for direct evaluation, lookup
lowering, and canonical AIR IR v2 serialization, producing exactly 46
source-bound selector artifacts. The historical receipt split proof grades by
contributor allocation. The active FV-1/FV-2 publication replaces that split
with one exact manifest-wide accepted-production-AIR theorem inventory,
organized by opcode family. The Sail side uses the pinned repository and
compiler, constructs the
exact `rv32im-zkvm-v1` configuration from the normative overrides, validates
that it reports `rv32im`, generates the theorem backend under that
configuration, and pins the complete generated file. Exact
`execute_UTYPE`/`execute_ITYPE`/`execute_RTYPE` slices are parsed fail-closed
into a typed AST and a canonical receipt records their normalized selector
effects. Direct generated-Lean equations bind every admitted execute-clause
input, including BTYPE, JAL, JALR, and FENCE.

The currently committed receipt remains deliberately called a **2/46
normalized pilot**, not “2 of 46 publication opcodes proved.” The exact
generated LUI/ADDI execute-clause
monads now normalize to the receipt-bound capsule, and the common sequential
next-PC/tick fragment composes with them. FV-1/FV-2 promotion is specifically
the replacement for that narrow receipt. Even after it lands, SA-1 remains
open until the FV-3/FV-4 global obligations in the status ledger are closed.
The generated manifest records narrow positive claims and negative global
claims, and fails closed if stale AIR or Sail artifacts are requested.

## 1. Objective and claim boundary

The project will prove a universal row theorem for every admitted opcode:

> Given a canonical instruction word, architectural pre-state, and memory
> observation admitted by the zkVM profile, every active row satisfying the
> production direct constraints, all activated fixed-table memberships, and
> the program/register/memory binding hypotheses projects to exactly the
> successful retirement produced by pinned Sail.

The projection includes all architecturally visible effects:

- decoded instruction identity;
- source-register values;
- destination-register presence, index, and value;
- next PC;
- load address and value;
- store address, width, mask, previous word, and next word;
- x0 behavior;
- instruction and access-clock tuples emitted to the cross-row relations; and
- absence of effects for instructions such as `FENCE`.

The theorem is universal over operands, register aliases, immediates, addresses,
memory words, and legal corner cases. It is not a finite enumeration of u32
values and is not inferred from uniqueness.

The completed result closes SA-1 premise 5. It does **not** by itself prove:

- that an accepted serialized proof binds an exact AIR witness;
- PCS commitment binding or FRI/list-decoding soundness;
- randomized LogUp soundness;
- Fiat–Shamir security;
- Poseidon2 collision resistance;
- the independent correctness of the proof-wire verifier; or
- byte compatibility with the retired Stark-V layout.

Those are computational-integrity obligations. In particular, this work must
not be described as a proof that every accepted production proof refines Sail
until SA-1 premise 1 has also been discharged under reviewed cryptographic
assumptions.

## 2. Why the existing evidence is insufficient

The repository already has unusually strong finite and row-local evidence:

- the runner agrees with pinned Sail and Spike on the committed formal corpus;
- 292 Sail-derived operand-class cases enter honestly admitted AIR rows;
- every one of the 17 AIR families has an end-to-end committed-row forgery;
- the production evaluator can emit canonical expression/lookup IR for all 17
  families;
- a fixed-seed extraction differential compares that IR with concrete
  evaluation;
- Z3 two-copy queries establish output uniqueness for the reviewed proof
  shards, including decomposed MULH and DIV arguments; and
- the independent Python AIR checker re-evaluates committed traces and global
  LogUp closure without sharing the Zig evaluator.

Each result answers a different question:

| Evidence | Question answered | Question not answered |
| --- | --- | --- |
| Sail/Spike corpus | Did these executions agree? | Do all admitted executions agree? |
| Operand classes | Did each reviewed boundary class agree? | Are values inside each class universally correct? |
| Mutation fleet | Do named forgeries fail? | Can an untested wrong transition satisfy the AIR? |
| Two-copy uniqueness | Is the row output functionally determined under the modelled premises? | Is the determined function Sail's function? |
| Python AIR checker | Does this exported committed trace satisfy a second evaluator? | Does every satisfying row refine Sail? |

A uniquely determined wrong function is still wrong. The missing result is
therefore a refinement proof, not another agreement sweep.

## 3. Formal objects

The mechanization will define the following objects explicitly.

### 3.1 Architectural values

- `U32`: a 32-bit word with modular arithmetic.
- `RegisterIndex`: a five-bit index.
- `Pc`: a profile-admitted, four-byte-aligned instruction address.
- `MemoryWord`: four little-endian bytes.
- `InstructionWord`: the canonical 32-bit fetched word.
- `PreState`: PC plus the register observations used by one retirement.
- `MemoryObservation`: the aligned containing word and effective address
  required by a load or store.
- `Retirement`: normalized successful Sail output containing next PC, optional
  register write, and optional memory effect.

The normalized retirement intentionally omits Sail implementation detail that
is not visible at the zkVM boundary. Every omitted field must be justified in
the Sail bridge and must not influence a later architectural transition.

### 3.2 AIR row values

An AIR family has:

- a fixed ordered column vector over M31;
- an active selector;
- direct constraint expressions that must vanish;
- fixed-table requests whose numerators determine whether the request is live;
- bus requests for `program_access`, `registers_state`, and `memory_access`;
- the opcode selector and decoded program fields; and
- a projection identifying the row's claimed architectural effect.

Rows are represented over `ZMod (2^31 - 1)`. Byte, nibble, 11-bit, 20-bit, and
M31 range membership are separate predicates. A field value is never treated
as a u32 merely because a witness-generation function originally received a
u32.

### 3.3 Local row environment

Cross-row LogUp closure is not reproved separately inside every opcode theorem.
Instead, the local theorem receives an explicit environment containing the
facts supplied by SA-1's cross-row lemmas:

- the `program_access` tuple binds `pc` to one canonical decoded instruction;
- each source-register tuple supplies the latest preceding value for its
  register key;
- a load/store memory tuple supplies the latest preceding aligned memory word;
- a destination tuple consumes the correct predecessor and publishes the row's
  claimed successor;
- live accesses use the production strict subclock ordering; and
- all values used in integer lifts satisfy the production no-wrap bounds.

These hypotheses are interfaces, not shortcuts. The row proof must still show
that the tuple fields emitted by the row are the fields required by the Sail
transition. It may not assume the destination value or next PC that it is
supposed to prove.

### 3.4 Pinned Sail step

`SailStep profile pre word memory` is the successful one-instruction transition
of the pinned Sail model, normalized to `Retirement`. Rejection, trap, and
environment-control outcomes are represented separately.

The proof-bearing language contains successful RV32IM retirements plus the
repository's single-hart `FENCE` interpretation. ECALL, EBREAK, disabled
extensions, malformed encodings, misalignment, and trapped executions have no
active opcode row. The conservative `FENCE.I` exclusion remains an explicit
profile narrowing.

## 4. Required theorems

The result is divided into four theorem classes so a proof cannot hide a decode
or interface assumption inside the arithmetic.

### 4.1 Admission and decode refinement

For every 32-bit instruction word:

1. if the zkVM admits it, the word has exactly one opcode-manifest entry;
2. the program tuple is the canonical projection of that word;
3. the projection identifies the same successful instruction as pinned Sail,
   except for the documented conservative profile exclusions; and
4. a word outside the proof profile cannot activate an opcode row.

This is a bitvector theorem over all words, not a loop over the committed
positive and negative vectors.

### 4.2 Fixed-table interpretation

For each fixed lookup domain, prove once that membership means the integer fact
used by opcode proofs:

- `bitwise`;
- `range_check_20`;
- `range_check_8_11`;
- `range_check_8_8_4`;
- `range_check_8_8`; and
- `range_check_m31`.

The theorem must account for the lookup numerator. A zero numerator means no
request; a live numerator must establish exact table membership. Bounds inferred
from a lookup may not be used before liveness is proved.

### 4.3 Opcode-row refinement

For every opcode `o`:

```text
RowActive o row
∧ DirectConstraintsHold o row
∧ FixedLookupsHold o row
∧ ProgramBinds env row word
∧ OperandsBind env row pre memory
∧ ProfileAdmits profile pre word memory
→ RowProjection o row env
    = SailRetirementProjection (SailStep profile pre word memory)
```

The Lean theorem will quantify over the row, state, word, and memory
observation. Each proof must establish both the architectural result and the
row's emitted relation tuples.

### 4.4 Non-vacuity

Every opcode needs a machine-checked existence theorem:

```text
∃ row pre word memory,
  RowActive o row
  ∧ DirectConstraintsHold o row
  ∧ FixedLookupsHold o row
  ∧ ProgramBinds ...
  ∧ OperandsBind ...
```

Without this, inconsistent constraints could make the refinement implication
vacuously true. The existing operand-class and honest witness generators can
provide concrete witnesses, but the resulting existence proof must be checked
by Lean against the same generated AIR definition.

## 5. Proof architecture

The implementation has four independently auditable stages:

```text
production Zig AIR                 pinned Sail model
       |                                  |
       v                                  v
canonical AIR IR                   generated Sail semantics
       |                                  |
       +-------------+  +-----------------+
                     v  v
               normalized Lean models
                     |
                     v
         per-opcode universal refinement proofs
                     |
                     v
       exact 46-opcode coverage and SA-1 premise 5
```

No Rust semantic oracle appears in this pipeline. Stark-V layout information is
irrelevant to the theorem.

### 5.1 Proof kernel

Lean 4 is the selected proof kernel. The repository will pin:

- the Lean toolchain;
- every non-core Lean dependency;
- the Sail compiler and theorem-backend invocation;
- generator source digests; and
- canonical generated AIR and Sail output digests.

The final CI result is a Lean kernel check. Z3 may generate counterexamples,
identify useful lemmas, or guide proof decomposition, but a Z3 `unsat` response
is not the publication artifact and is outside the trusted proof conclusion.

### 5.2 Lean representations

The preferred representations are:

- M31 values as `ZMod 2147483647`;
- architectural words as `BitVec 32`;
- bytes as `Fin 256`;
- register indices as `Fin 32`;
- fixed-size row columns as `Fin n → ZMod p`;
- range-table meanings as arithmetic predicates rather than enumerated arrays;
  and
- normalized Sail retirement effects as a small structure with optional writes.

The bridge library will prove:

- canonical byte recomposition and decomposition;
- injectivity of bounded integer embeddings into M31;
- when a field equality can be lifted to an integer equality;
- two's-complement sign-extension lemmas;
- u32 addition/subtraction wraparound;
- bit extraction and mask lemmas;
- aligned address split/recomposition;
- strict access-subclock encoding; and
- quotient/remainder corner-case lemmas used by RV32M.

Proofs should use kernel-checked simplification, arithmetic normalization, and
bitvector reflection. Native execution or an external solver must not introduce
an unreviewed axiom into the core theorem.

## 6. Binding the proof to the shipped AIR

This is the most important engineering risk. A beautiful proof of a manually
rewritten AIR is not a proof of the production system.

### 6.1 Current extraction

`src/frontends/riscv/air/extract/mod.zig` evaluates the generic production
semantics and lookup-entry construction with a symbolic scalar and emits:

- ordered columns and roles;
- the expression DAG;
- direct constraint roots;
- lookup numerators, domains, tuples, and labels; and
- row inputs and architectural outputs.

It also runs an eight-assignment-per-family, fixed-seed differential between
the recorded DAG and the QM31 instantiation of the same production source.
The dedicated `riscv-refinement-ir` build root executes this frontend-owned
extractor directly. Its default output is cleared first; a caller-supplied
output must be absent or empty. The public pilot gate additionally rejects a
missing, extra, or empty family before normalization. This is a strong pilot
foundation, but the random differential is not a universal source-binding
proof.

### 6.2 Canonical refinement IR

AIR IR v2 is delivered for all 17 families and 46 selectors as a distinct,
versioned production-program wire while the original all-family symbolic
export remains the Level-1 normalizer input for LUI/ADDI. The canonical
production IR contains:

- schema version;
- opcode selector and exact manifest entry;
- production source-path and source-digest manifest;
- family and opcode IDs;
- column names, indices, roles, and widths;
- active-row predicate;
- every direct constraint in evaluation order;
- every fixed-table and bus request;
- decoded program-field projection;
- architectural effect projection;
- access ordinals;
- table schema digests;
- M31 modulus and integer-bound metadata; and
- a canonical content digest.

Generated files are deterministic and duplicate JSON fields are rejected.
Column, constraint, lookup, or table-order drift changes the digest.
Strict Python and Lean decoders reject noncanonical JSON, malformed or dead
DAGs, reordered event/projection structure, incorrect table metadata, invalid
selector placement, and source-closure drift.

### 6.3 Binding gates

There are two acceptable implementation levels:

1. **Pilot binding:** invoke the same generic Zig semantics functions used by
   production with the symbolic IR collector, pin the emitted digest, and keep
   the existing concrete differential as a fail-closed regression.
2. **Publication binding:** make the production evaluator and the Lean export
   consume one canonical constraint program by construction, or produce a
   kernel-checkable translation certificate showing that every production
   evaluator event occurs in the exported program with the same operands and
   order.

Level 1 is sufficient to develop LUI, ADDI, load, and DIV proofs. The project
must not claim a universal theorem about the shipped AIR until level 2 is
complete. Random testing, however extensive, cannot substitute for it.

The preferred level-2 design is now instantiated across all 46 selector
programs: a single typed `ConstraintProgram` builder is interpreted by
production over concrete field expressions and lookup views, serialized by the
exporter, and interpreted by Lean. A fresh-export equality gate prevents a
shape-preserving replacement artifact from relying on self-authentication
alone. All 24 Team A selectors have per-opcode theorems over their exact
generated local programs, tuple projections, non-vacuity witnesses, and
mutations. The 22 Team B selectors remain bound to reviewed family capsules
rather than exact generated local programs. Across both teams, only LUI and
ADDI are normalized through generated Sail retirement; neither the remaining
44 retirement normalizations nor the converse accepted-AIR soundness theorem
is established in the currently committed receipt. The active FV-1/FV-2
promotion replaces this historical split with 46 generated normalizers and 46
accepted-production-AIR implications; those count only after the integrated
audit, receipt, reproduction, and merge gates pass.

## 7. Binding the proof to pinned Sail

The other unacceptable shortcut is a hand-written “Sail-like” Lean function.

### 7.1 Generated semantics

The pinned Sail model must be compiled through a theorem-prover backend into a
Lean-consumable transition definition. The generation receipt binds:

- Sail repository and commit;
- Sail compiler version;
- exact model entry points;
- RV32 configuration and extension settings;
- repository-owned profile normalization;
- generated-file digests; and
- the normalization bridge version.

The RVFI transport entry patch used by executable differential testing is not an
ISA semantic rule and must not silently enter the theorem model.

### 7.2 Normalization bridge

Raw generated Sail state is expected to be much larger than one zkVM retirement.
A reviewed bridge maps it to the repository's normalized `Retirement`:

- `next_pc`;
- optional `(rd, value)`;
- optional memory read observation;
- optional masked memory write;
- success/rejection classification; and
- no other externally visible state change.

For every admitted opcode, Lean must prove that normalization preserves all
fields observed by the next transition. The bridge may erase logging,
interpreter bookkeeping, or inactive extension state only after proving it
irrelevant.

If the pinned Sail revision cannot be compiled directly into usable Lean, the
fallback is a generated normalized semantics capsule plus a checked translation
receipt from the Sail AST. Hand-transcribing 46 instruction functions and
validating them only with test vectors is not an acceptable fallback.

The LUI/ADDI pilot now carries that checked translation artifact: exact
generated `execute_UTYPE` and `execute_ITYPE` slices, their typed AST digests,
and a fail-closed canonical receipt for every selector in those definitions.
Carried-evidence runs re-derive it byte for byte; only a live pinned-toolchain
run can mint release evidence. The cross-project proof at
`formal/riscv-refinement/generated-sail-bridge/Pilot.lean` additionally imports
the exact generated Lean project and proves that the LUI/ADDI clause monads
plus sequential next-PC/tick fragment equal the normalized executions. Its
receipt explicitly leaves fetch, interrupt, trap, counter, and later-step
framing false; it does not constitute the independent fallback approval
required by the Team B contract.

### 7.3 Decode narrowing

The Sail bridge owns one explicit difference: the zkVM rejects `FENCE.I` while
the pinned model currently retires it despite the disabled Zifencei setting.
The admission theorem expresses the zkVM language as a conservative subset and
proves refinement only for that subset. It must not weaken or override the
semantics of an admitted instruction.

## 8. Pilot: LUI and ADDI

The Level-2 publication milestone is complete only when both opcodes are
universally proved and non-vacuous from generated AIR and generated Sail
definitions. The current pilot proves source-bound, interpreted production AIR
programs imply the normalized LUI/ADDI predicates, and the normalized capsule
is bound to actual generated execute clauses by the checked AST receipt and a
kernel-checked clause-monad equality. The remaining publication gap is full
generated Sail step-loop framing (or the contract's independently approved
fallback), not AIR interpretation or execute-clause transcription.

### 8.1 LUI

LUI is the minimal vertical slice. The proof covers:

- U-type decode and canonical immediate projection;
- all 20-bit immediates;
- placement in bits 31:12;
- zero low 12 bits;
- all destination registers, including `rd = x0`;
- next PC;
- the program tuple;
- source-free register-state behavior; and
- destination relation emission.

LUI is intentionally first because a failure is likely to indicate a broken
translation or theorem interface rather than difficult arithmetic.

### 8.2 ADDI

ADDI validates the first reusable arithmetic library. The proof covers:

- I-type decode;
- every sign-extended 12-bit immediate;
- byte decomposition;
- carry constraints;
- u32 modular addition;
- positive and negative immediates;
- overflow and underflow;
- `rd = rs1` source-before-destination aliasing;
- `rd = x0`;
- next PC; and
- exact register/program relation tuples at derived access subclocks.

The pilot fails if it proves only an ADDI output formula while ignoring the
source read, destination predecessor, tuple clock, or x0 path.

### 8.3 Pilot exit criteria

- `lake build` checks both theorems from a clean checkout.
- `#print axioms` reports no unapproved axiom for either theorem.
- No `sorry`, `admit`, theorem-local `axiom`, or opaque unchecked certificate is
  present.
- AIR and Sail generated digests are pinned in one receipt.
- Honest existence theorems establish non-vacuity.
- Removing the LUI low-limb constraint breaks its proof or yields a checked
  counterexample.
- Removing an ADDI carry/range obligation breaks its proof or yields a checked
  counterexample.
- The existing Sail corpus and Zig exhaustive tests remain green.

## 9. Stress validation: signed load and DIV

The pipeline is not considered scalable merely because LUI and ADDI work.
Before broad rollout it must survive one memory-heavy family and the hardest
integer-arithmetic family.

### 9.1 Signed LH stress case

The load milestone proves `LH` universally, including:

- I-immediate address calculation with wraparound;
- natural halfword alignment;
- low-half and high-half selection from the aligned memory word;
- little-endian byte order;
- negative and nonnegative halfwords;
- sign extension to 32 bits;
- `rd = rs1` aliasing;
- memory read-only preservation;
- register and memory access order;
- effective address and aligned-word bus tuples; and
- the destination write.

An honest witness must include a negative high-half case, because a zero or
positive low-half witness would not exercise the sign path. After `LH`, the
same bridge must be capable of proving `LB`, `LW`, `LBU`, and `LHU` without
changing the theorem interface.

### 9.2 DIV-family stress case

The DIV milestone covers all four selectors—`DIV`, `DIVU`, `REM`, and
`REMU`—because their shared AIR contains selector-dependent corner cases. It
must prove:

- byte/carry recomposition of dividend, divisor, quotient, and remainder;
- signed and unsigned interpretations;
- quotient truncation toward zero;
- remainder magnitude and sign;
- divisor zero conventions;
- signed overflow at `INT_MIN / -1`;
- high-bit unsigned operands;
- quotient-sign witness binding;
- the nonzero-divisor comparison witness; and
- exact destination and relation projections.

Required named witnesses include signed overflow, signed negative remainder,
zero divisor, and the historical high-bit `0x8abcdef1 / 1` DIVU case.

Z3 may continue to supply the existing arithmetic decomposition as a discovery
aid. The final DIV theorem and its supporting integer lemmas must be checked by
Lean.

### 9.3 Stress-gate decision

If either LH or the DIV family requires a different semantic model, AIR IR, or
row-environment interface, the design is revised before any additional family
is claimed. This gate exists to prevent scaling a pilot architecture that works
only for straight-line ALU rows.

## 10. Scaling across all 46 opcodes

The implementation scales by 17 AIR-family proof frameworks, but completion is
tracked by opcode. A family theorem with an unproved selector case does not
cover that opcode. The graded rollout now covers exactly 46/46 selectors; the
table remains the normative publication inventory, because a graded
certificate is not automatically a generated-Sail retirement theorem.

| AIR family | Opcodes | Count | Principal proof obligations | Risk |
| --- | --- | ---: | --- | --- |
| `base_alu_reg` | ADD, SUB, XOR, OR, AND | 5 | byte/carry or bitwise result, aliases | medium |
| `base_alu_imm` | ADDI, XORI, ORI, ANDI | 4 | sign extension, byte/carry, bitwise | medium |
| `shifts_reg` | SLL, SRL, SRA | 3 | masked shift amount, carries, sign fill | high |
| `shifts_imm` | SLLI, SRLI, SRAI | 3 | immediate decode, carries, sign fill | high |
| `lt_reg` | SLT, SLTU | 2 | signed/unsigned comparison | medium |
| `lt_imm` | SLTI, SLTIU | 2 | immediate sign extension and comparison | medium |
| `branch_eq` | BEQ, BNE | 2 | predicate and two next-PC paths | medium |
| `branch_lt` | BLT, BGE, BLTU, BGEU | 4 | signedness, predicate complement, target | high |
| `lui` | LUI | 1 | U-immediate projection | low |
| `auipc` | AUIPC | 1 | U-immediate, PC addition, rd/x0 behavior | medium |
| `jalr` | JALR | 1 | signed immediate, wraparound, bit-zero clear, target bound | high |
| `jal` | JAL | 1 | J-immediate, link value, target | medium |
| `load_store` | LB, LH, LW, LBU, LHU, SB, SH, SW | 8 | memory word masks, sign, preservation, aliases | high |
| `mul` | MUL | 1 | low product and carry recurrence | high |
| `mulh` | MULH, MULHSU, MULHU | 3 | signed 64-bit product and high projection | very high |
| `div` | DIV, DIVU, REM, REMU | 4 | quotient/remainder and exceptional cases | very high |
| `fence` | FENCE | 1 | decode, PC+4, absence of effects | low |
| **Total** |  | **46** |  |  |

Recommended promotion order from graded evidence to publication evidence:

1. LUI, FENCE, JAL;
2. base ALU register/immediate;
3. comparisons and branches;
4. shifts;
5. AUIPC and JALR;
6. remaining loads and stores;
7. MUL;
8. MULH variants; and
9. remaining DIV/REM selector cases.

Within each family, shared lemmas are proved once and selector-specific
theorems instantiate them. Coverage automation compares theorem names and
opcode IDs against `src/frontends/riscv/opcode_manifest.zig`; an omitted,
duplicated, or renamed opcode fails closed.

## 11. Repository layout

The implementation should use one self-contained formal project:

```text
formal/riscv-refinement/
  lean-toolchain
  lakefile.toml
  lake-manifest.json
  RiscvRefinement/
    Common.lean
    Air/
      Generated/
    Sail/
      Generated/
    Bridge/
      Decode.lean
    Opcodes/
      Lui.lean
      Addi.lean
    Coverage.lean
    NonVacuity.lean
    AxiomAudit.lean
  generated/
    air/
    sail/
  generated-manifest.json
  refinement-receipt.json
```

The smaller `Field`, AIR interpreter/table, tuple-bridge, memory, and
family-specific modules shown in earlier design revisions remain the intended
Level-2 expansion. They should be introduced when they own real checked
objects rather than as empty package ceremony.

Repository tooling should be owned under:

```text
scripts/riscv_refinement.py
scripts/riscv_refinement_lib/
```

The tool owns generation, digest checking, coverage reporting, and clean-room
reproduction. It does not prove theorems itself.

Generated Lean files may be committed if that materially improves review and
offline reproducibility. If committed, CI regenerates them into a temporary
directory and requires byte identity. Generated files are never edited by
hand.

## 12. Build, reproduction, and change control

The pilot exposes the following interfaces:

```sh
# One-time, after preparing the pinned formal-tool workspace:
python3 scripts/riscv_refinement.py prepare-sail \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv

# Generate or reproduce committed inputs. The default standalone export is
# freshly replaced; -Driscv-refinement-ir-dir=... must name an absent or empty
# directory:
zig build riscv-refinement-ir
python3 scripts/riscv_refinement.py generate
python3 scripts/riscv_refinement.py check-generated
python3 scripts/riscv_refinement.py coverage
(cd formal/riscv-refinement && lake build)

# Complete public pilot gate:
zig build riscv-refinement-pilot

# Clean-tree evidence:
python3 scripts/riscv_refinement.py receipt
python3 scripts/riscv_refinement.py verify-receipt
```

`prepare-sail` writes the merged exact-profile configuration and generates the
external theorem backend. The repository's existing
`scripts/riscv_formal_tools.py` owns pinned checkout/compiler/simulator
preparation. `riscv-refinement-pilot` first runs the dedicated production IR
export and then checks byte-identical generation, 2/46 normalized coverage,
46/46 graded coverage, negative controls, Python infrastructure tests, the
pinned Lean build, and the complete axiom audit.

`--no-export-air` exists only so the root build step can consume the exporter
it already depends on. Receipt generation rejects that switch and always
exports into a fresh staging directory before atomically replacing the
ignored `zig-out/uniqueness-ir` tree.

### 12.1 Required PR checks

The hosted gate is split by capability. On pull requests,
`.github/workflows/riscv-refinement.yml` freshly exports all 17
families and 46 selector programs, checks the grade-preserving certificate
index, builds the complete Lean project, runs non-vacuity and mutation shards,
scans for proof escapes, and audits axioms. It consumes the committed
generated-Sail receipt and does not pretend to have regenerated Sail.
`.github/workflows/riscv-sail-formal.yml` separately provisions Sail 0.20.2,
regenerates the pinned theorem backend, runs the live pilot, and mints live
evidence on pushes to `main`, schedules, and explicit dispatches. The focused
RISC-V product and release gates also run the cheap aggregate certificate and
current-source identity check; that check detects stale formal inputs but does
not substitute for a Lean or live-Sail run.

Every pull request touching the following surfaces triggers the fast
refinement build:

- `src/frontends/riscv/opcode_manifest.zig`;
- `src/frontends/riscv/isa/**`;
- `src/frontends/riscv/air/semantics/**`;
- opcode trace columns or lookup-entry generation;
- fixed lookup-table schemas;
- program decode;
- access-clock encoding;
- generated AIR IR or its generator;
- Sail pin, compiler, configuration, or normalization;
- Lean proof sources; or
- refinement manifests and receipts.

The check fails on:

- generated drift;
- unknown IR schema;
- a changed source or table digest;
- an uncovered opcode;
- any `sorry` or unapproved axiom;
- theorem build failure;
- missing non-vacuity;
- a changed Sail normalization surface;
- timeout in a required kernel proof; or
- a proof that depends on an undeclared package.

### 12.2 Tiering

- **Fast graded PR CI:** fresh production AIR, exact 46/46 grade-preserving
  coverage, every current Lean theorem and non-vacuity witness, mutations,
  proof-escape scan, and axiom audit.
- **Live Sail CI:** regenerate the pinned generated-Sail backend, rebuild the
  current 2/46 normalized pilot, and mint live evidence.
- **Publication CI:** all 46 generated-Sail retirement theorems, the
  accepted-AIR soundness direction, Word32/M31 boundary lemmas, and trace
  composition. This tier is not yet implemented.
- **Scheduled clean-room build:** regenerate pinned Sail and AIR definitions
  from empty caches, build every theorem, and publish a signed receipt.

Semantic changes must keep the fast graded check on every PR. A nightly-only
universal theorem is too weak for a release branch; when publication CI is
implemented, its affordable source-bound portion must become PR-blocking.

### 12.3 Receipt

The issue #136 A5 graded-integration receipt contains:

- schema;
- implementation commit and dirty state;
- Lean version and dependency lock digest;
- Python, Zig, Lake, and Lean binary identities;
- Sail repository, commit, compiler version, profile, and exact configuration
  digests through the portable generated manifest;
- platform-local Sail compiler and simulator binary identities in the receipt;
- AIR IR schema and per-opcode digests;
- generator digests;
- 46 grade-preserving opcode/theorem, tuple, non-vacuity, mutation, AIR, and
  Sail mappings: 24 exact generated local programs and 22 reviewed capsules;
- theorem build result;
- declared axioms for every exported theorem;
- the exact `24/24 AIR`, `46/46 graded`, `2/46 normalized`, `0/46
  publication`, full-step, proof-system, whole-frontend, and external-signoff
  claim boundary;
- negative-control identities; and
- final canonical receipt digest.

The final publication receipt must additionally carry all 46 generated-Sail
retirement theorem identities, the accepted-AIR soundness and trace-composition
theorems, the complete M31/Word32 conversion inventory, the five closure-gate
results from §15.1, and the required independent sign-offs. Timing is
diagnostic. Coverage, pins, hashes, theorem results, and sign-offs are
normative.

## 13. Proof-review discipline

Every family requires three reviewers with distinct questions:

1. **AIR reviewer:** does the generated row projection correspond to the
   production columns and relation tuples?
2. **Sail/profile reviewer:** does the normalized Sail result preserve every
   field visible to the zkVM?
3. **formal-proof reviewer:** do the lemmas prove the stated universal result
   without hidden axioms, vacuity, or unjustified integer lifts?

The same person may implement more than one layer, but the Sail normalization
bridge and the AIR source-binding gate require independent sign-off.

Proof review uses generated names and source anchors. A 500-line tactic proof
that no longer exposes which constraint or lookup supplies a fact must be
refactored before acceptance.

## 14. Negative controls

Green theorem builds need demonstrated sensitivity. The refinement tooling will
maintain mutation controls that alter generated input in a temporary directory
and require either:

- a Lean proof failure; or
- a concrete counterexample checked against the mutated AIR and pinned Sail.

Mandatory pilot/stress mutations include:

- free LUI low immediate limb;
- deleted ADDI carry or immediate-range request;
- free LH sign witness;
- unpreserved load memory word;
- non-byte DIV divisor limb;
- free DIV quotient sign;
- deleted zero-divisor convention;
- JALR target-bit release; and
- one selector relabelling inside each shared family.

These controls do not strengthen the theorem; they establish that the pipeline
is connected to the obligations it claims to prove.

The current LUI/ADDI Stage A2 controls are Lean-checked against the interpreted
production programs. They construct witnesses for a free LUI low limb, deleted
ADDI high carry, deleted immediate-range request, selector relabel, and event
reorder, and prove each weakened system strictly loses the stated
architectural or binding fact. They reach the kernel proof and no longer rely
only on the Python normalizer. They are still stated against the normalized
capsule; the open generated-Sail fetch/interrupt/trap/counter and later-step
framing boundary prevents treating them as end-to-end Sail publication
controls.

## 15. Work packages and gates

### UR-00 — theorem and trusted-base freeze

Status: **AIR-side pilot freeze delivered**. The theorem signatures, toolchain,
closed pilot schemas, all-selector AIR IR v2 contract, LUI/ADDI serialized-AIR
interpreters and composition, digest closure, axiom policy, generated execute
translation receipt, direct generated execute-clause monad bridge, and claim
boundary are implemented. Full generated-Sail step-loop framing and the
required sign-off remain open for publication.

Deliver:

- this document reviewed;
- Lean toolchain decision and dependency policy;
- exact theorem signatures;
- AIR IR v2 schema;
- Sail generation experiment; and
- a written trusted computing base.

Exit gate: reviewers agree what a green theorem does and does not mean.

### UR-01 — formal foundations and LUI

Status: **production AIR-to-normalized slice delivered**. The typed
word/byte/M31 foundations, exact LUI shape gate, universal normalized theorem,
non-vacuity witness, source-bound production program, strict Lean evaluator,
composition with `LuiHolds`, and a Lean-checked mutation are present. The
execute clause and sequential PC/tick fragment are kernel-bound to generated
Sail; clean publication remains open across the full step-loop/sign-off
boundary.

Deliver:

- M31, u32, byte, range, and tuple libraries;
- generated LUI AIR;
- generated Sail LUI semantics;
- universal LUI refinement;
- LUI non-vacuity; and
- mutation control.

Exit gate: clean kernel proof from pinned generated inputs.

### UR-02 — ADDI vertical slice

Status: **production AIR-to-normalized slice delivered**. Sign extension, byte
carries, modular addition, source preservation, alias/x0 behavior, interpreted
production-program composition, non-vacuity, and the Stage A2 mutation bundle
are kernel checked. The execute clause and sequential PC/tick fragment are
kernel-bound to generated Sail; the full step-loop/sign-off boundary remains.

Deliver:

- sign-extension and carry library;
- strict register-access bridge;
- universal ADDI refinement;
- alias and x0 cases;
- ADDI non-vacuity; and
- mutation controls.

Level-2 exit gate: the production-to-generated-clause path works for a
nontrivial arithmetic row. Its full generated Sail step-loop/sign-off side
remains open.

### UR-03 — memory stress

Status: **reviewed-capsule stress mechanization delivered by Team B**. All
eight load/store selectors have normalized refinements, non-vacuity, and
load-bearing mutation controls, including signed high-half LH and the closed
high-address alias regression. Generated-Sail slices/receipts and step
composition remain open, so this is not publication coverage.

Deliver:

- memory-observation and masked-word model;
- address/alignment lemmas;
- universal LH refinement;
- negative high-half witness;
- memory tuple bridge; and
- mutation controls.

Exit gate: no theorem-interface redesign is required for the remaining
load/store selectors.

### UR-04 — DIV stress

Status: **reviewed-capsule stress mechanization delivered by Team B**. DIV,
DIVU, REM, and REMU cover the named exceptional cases with normalized
refinements, non-vacuity, and mutation controls. Generated-Sail
slices/receipts and step composition remain open, so this is not publication
coverage.

Deliver:

- checked quotient/remainder library;
- all four DIV/REM selector theorems;
- every exceptional case;
- non-vacuity witnesses; and
- mutation controls.

Exit gate: the proof architecture handles the repository's hardest arithmetic
without treating solver output as an axiom.

### UR-05 — complete 46-opcode rollout

Status: **historical graded rollout delivered; neutral publication promotion
in progress**. The old receipt partitions the manifest exactly 46/46 but does
not establish publication-level refinement. FV-1/FV-2 must replace it with one
46-opcode inventory whose theorem strength is uniform and contributor-neutral.

Deliver:

- all remaining family lemmas;
- exact opcode coverage;
- all non-vacuity theorems;
- full negative-control manifest; and
- bounded, reproducible proof times.

Exit gate: coverage matches the opcode manifest exactly.

### UR-06 — production source binding

Status: **shared 46-program source binding delivered; uniform local
publication pending final FV-2 integration**. Direct evaluation, lookup
lowering, and AIR IR v2 serialization share one typed production program;
canonical generation, strict source closure, fresh-export equality, and Lean
decode/evaluation are checked. The remaining local gate is one exact
accepted-AIR implication per manifest opcode plus the aggregate theorem,
axiom audit, receipt, and reproduction.

Deliver:

- one canonical constraint program used by production and formal export, or an
  equivalent checked translation certificate;
- per-opcode production digests;
- clean regeneration; and
- source-change invalidation tests.

Exit gate: the theorem is legitimately about the shipped AIR, not merely the
pilot export.

### UR-07 — SA-1 integration and research artifact

Deliver:

- SA-1 premise 5 marked machine-proved;
- public theorem and assumption index;
- clean-room reproduction package;
- proof statistics and engineering evaluation;
- external replication; and
- paper-ready description of the generated refinement pipeline.

Exit gate: a third party can regenerate the models and kernel-check every
opcode theorem from the pinned inputs.

### 15.1 Normative remaining closure gates

The graded 46/46 index is an input to these gates, not evidence that they have
already passed. “Universal AIR → Sail refinement,” “formally verified
frontend,” and `whole_frontend_verified = true` are forbidden until **all
five** gates below are satisfied by named kernel theorems and one
machine-readable publication receipt.

#### FV-1 — generated Sail retirement and full-step framing

For every one of the 46 admitted selectors, normalize the exact pinned
generated-Sail execute clause to the repository retirement projection and
prove its composition with the generated fetch/decode/execute step. The proof
must cover the profile's interrupt, trap, counter, next-PC/tick, and later-step
framing, or use the independently approved fallback specified by the
generated-Sail composition contract. A generated-clause input equation and a
reviewed capsule are not
retirement normalization.

Exit evidence:

- `normalized_retirements.proved = 46`;
- one generated-Sail retirement theorem and source digest per opcode;
- `full_generated_sail_step = true`; and
- no hand-written semantic function accepted as generated Sail without the
  checked translation and independent fallback approvals.

The stable FV-1 kernel surface is:

- `LeanRV32IM.Functions.complete_<OP>_normalizes`, exactly once for each
  manifest selector and in manifest order;
- `LeanRV32IM.Functions.generated_full_step_retirement_composition`, retaining
  the generated step outcome and distinguishing successful retirement from
  interrupt, trap, and fetch failure while preserving the generated
  counter/tick postlude; and
- the two-file bridge source closure
  `generated-sail-bridge/{Pilot,Composition}.lean`, where `Pilot.lean` is
  compiled to a temporary `Pilot.olean` and `Composition.lean` imports that
  exact artifact. Both source digests are part of the receipt.

The generated-Sail source receipt must bind each selector to the digest of its
exact generated execute definition. A family-shared generated definition may
therefore repeat a digest, but an unordered family digest cannot stand in for
46 ordered selector records.

Full-step specialization must start from componentwise generated-state and
profile bindings, not from a premise asserting the desired monad result or
final state. At minimum these bindings cover active-hart state, PC and
register-file contents, the fetched program word, interrupt/profile state, and
the postlude counters consulted by the generated loop. For memory selectors
they also prove that ordinary RAM, rather than platform MMIO, handles the
access. In the pinned generated model this means proving
`htif_tohost_base = none` (or an equally strong disjoint-address fact), Bare
translation, and non-reservation load/store arguments. The generated Lean
source mentions `plat_term_write`, `load_reservation`, `match_reservation`,
and `sys_enable_experimental_extensions` transitively; the receipt records
that exact syntactic axiom footprint, while the opcode theorem must prove the
corresponding branches unreachable under the admitted profile. Merely adding
those callbacks to an axiom allowlist does not discharge the profile
obligation.

#### FV-2 — accepted production AIR implies the Sail transition

The required direction is:

```text
active production row
∧ production direct constraints hold
∧ every live fixed-table and relation request holds
∧ program/register/memory bindings hold
∧ the zkVM profile admits the transition
→ exact generated-Sail retirement
```

A theorem whose strongest chain is only “reviewed semantic predicate → AIR
roots/lookups” does not satisfy this gate: it shows that a good execution can
populate the AIR, not that every AIR-accepted execution is good. Each theorem
must derive its semantic predicate from the accepted production row, include
the exact ordered tuple projection, prove selector/admission uniqueness, and
retain a non-vacuity witness and load-bearing mutation. Every historical
reviewed capsule must be promoted to an exact generated local program or
receive an equivalent checked translation certificate.

Exit evidence:

- 46 theorem identities with the accepted-AIR implication above;
- 46 exact production-program identities;
- universal admission/decode and fixed-table interpretation theorems; and
- `publication_level.proved = 46`.

The stable FV-2 cross-project theorem identity for selector `<OP>` is
`LeanRV32IM.Publication.<OP>_accepted_air_refines`. Each of these 46 theorem
statements must quantify directly over the concrete typed row and witness, its
exact `LocalProgram.evalSymbolic` evaluation, an
`AcceptedProductionEvaluation` carrying direct, fixed, and live relation
acceptance, the program/register/memory environment, and profile admission.
A premise that already asserts the family `Holds` predicate, the expected
retirement, an internal carry/result equality, or a prebuilt publication
certificate is forbidden. A generated full-step outcome, decoder-result
equality, or final-state equality is forbidden for the same reason. The
cross-project theorem may consume the componentwise program, register, memory,
and generated-profile bindings described above; it must derive decoder
agreement and the successful generated retirement internally.

At this row-local gate, non-vacuity means that the bound
`runBaseAfterDecode`/execute path has a successful generated execution whose
observed retirement is the AIR retirement; a theorem that only constrains a
hypothetical successful trace is insufficient. Constructing one complete
multi-row `try_step` execution, including each fetch from the committed
program image, belongs to FV-4. FV-1 still supplies the premise-free theorem
that the retained full-step trace erases to that exact generated `try_step`,
so this split does not replace the generated loop with a hand-written one.

`LeanRV32IM.Publication.universal_publication_contract` must have a concrete
type that contains all 46 exact cross-project propositions plus
`generated_full_step_retirement_composition`; it is not sufficient for those
names merely to exist. The generated bridge axiom audit therefore contains
exactly 94 receipt records: 46 normalization theorems, 46 cross-project
theorems, the full-step theorem, and the typed universal contract.

The repository-side receipt additionally requires
`exactProductionProgramIdentities`, `exactProductionProgramCount`,
`exactProductionManifestOrder`, `exactProductionManifestIdsNodup`,
`exactProductionMnemonicUnique`, `universalAdmissionDecode`,
`universalFixedTableSchemas`, `universalFixedTableInterpretation`,
`exactLocalManifestCoverage`, `exactLocalManifestOrderFilter`, and
`exactLocalTheoremIdentityCoverage`. These facts establish one exhaustive,
duplicate-free 46-opcode publication inventory rather than preserving the
historical contributor-team partition or assembling a count from theorem-name
metadata.

#### FV-3 — M31/Word32 representation and global invariant closure

M31 arithmetic is modulo \(p = 2^{31}-1\); RV32 machine-word arithmetic is
modulo \(2^{32}\). `composeU32` is therefore non-injective over arbitrary byte
limbs. Every conversion from a machine-width limb value to one field element
must name and discharge the premise that makes the conversion injective, and
every field addition/subtraction used as integer arithmetic must separately
prove that its complete integer range does not cross the field modulus.

This gate includes all current production arithmetic/equality sites in
`load_store`, `auipc`, `jalr`, and `jal`. A site is acceptable only when its
bounding constraint or limb-keyed representation is cited in the theorem and
is derived from the accepted AIR or a proved cross-row invariant. An external
Lean premise, a producer-byte convention, an admission profile, or reviewer
memory is not enough unless the final composition theorem proves that the AIR
and buses establish it. Memory or state buses that depend on architectural
distinctness must be keyed by limbs or prove that their single-field key is
injective over the admitted domain.

Exit evidence:

- a complete, machine-checked inventory of machine-word-to-field conversions;
- a mechanical gate that rejects any unregistered `composeU32` use or
  equivalent implicit composition;
- per-site bounded-lift and no-wrap theorem identities;
- the concrete `ALIASING_BASE = 0x7FFFFFFB` negative witness at every affected
  site, with the honest row accepted and the aliased row rejected; and
- non-vacuous, mutation-pinned controls proving that each bound is
  load-bearing.

#### FV-4 — trace and cross-row composition

Compose the 46 accepted-row theorems over a complete admitted execution, not
only isolated rows. The theorem must connect program binding, register-state
and memory buses, strict access clocks, state-chain telescoping, initial and
final public boundaries, profile restrictions, and every emitted tuple to the
corresponding sequence of pinned generated-Sail transitions. It must discharge
or cite machine-checked forms of the five cross-row obligations CR-1 through
CR-5 in
[`SAIL_AIR_COMPOSITION.md`](SAIL_AIR_COMPOSITION.md).

Exit evidence:

- a named trace-refinement theorem quantified over every admitted trace length;
- no row-local environment fact left as an unproved global premise;
- the exact SA-1 premise-5 theorem and receipt identity; and
- explicit separation from SA-1 premise 1: frontend trace refinement does not
  establish PCS/FRI/Fiat–Shamir or randomized-LogUp soundness.

#### FV-5 — independent review, reproduction, and claim promotion

The publication receipt must record accountable review for production AIR and
tuple projection, generated Sail and execution profile, memory stress,
division stress, and independent Lean soundness/non-vacuity. Contributor-team
labels are historical and cannot satisfy a review role. A third party must
reproduce the AIR and generated-Sail inputs from empty caches and kernel-check
the exact theorem inventory.

Only after FV-1 through FV-5 pass may the receipt set
`whole_frontend_verified = true`. `proof_system_soundness` remains false until
the independent SA-1 premise-1 reduction is complete; frontend verification
must not silently promote the cryptographic proof-system claim.

### 15.2 Operational adoption audit (2026-07-30)

| Consumer | Current use of the formal work | Assessment |
| --- | --- | --- |
| Production direct constraints | All 17 families use `ConstraintProgram.buildDirect` | strong: production and formal export share construction |
| Production relation lookups | All 17 families use `ConstraintProgram.buildLookups` | strong: tuple order is not maintained in a second semantic implementation |
| AIR IR v2 export | The same builder emits 46 selector programs with source closure and fresh-export checks | strong |
| Focused product and release gates | Run the aggregate 46/46 certificate and current-source identity check | useful cheap fail-closed consumption; not a Lean substitute |
| Pull-request formal gate | Fresh AIR export, complete graded Lean build, mutations, proof-escape scan, and axiom audit | strong |
| Live generated-Sail gate | Pinned Sail provisioning, backend regeneration, current 2/46 normalization, and receipt minting on `main`/schedule | correctly separated from carried-evidence PR CI |
| Runtime frontend binary | Does not load Lean artifacts or proof receipts | correct: proofs constrain development and release, not runtime semantics |
| Machine-word/field API | Raw `composeU32` remains available and six production sites rely on site/global reasoning | incomplete; FV-3 is not mechanized |
| Generated-Sail publication | 2/46 normalized, 0/46 publication-level | incomplete; FV-1 and FV-2 dominate the remaining work |
| Whole-trace theorem and sign-off | Not established | incomplete; FV-4 and FV-5 remain blocking |

## 16. Principal risks and mitigations

| Risk | Failure mode | Mitigation |
| --- | --- | --- |
| AIR translation gap | Proof covers a model different from production | Single-source constraint program or checked translation certificate |
| Sail backend complexity | Generated state is too large or unsupported | Prove a reviewed normalization bridge; do not hand-recode semantics |
| Vacuous implication | Inconsistent AIR “proves” everything | Per-opcode existence theorems and honest witnesses |
| Field/integer confusion | M31 equality is lifted past wraparound | Central bounded-lift lemmas with explicit hypotheses |
| Lookup liveness error | Range fact is inferred from an inactive request | Prove numerator liveness before table membership |
| Bus/local mismatch | Row output is right but emitted tuple is wrong | Include all bus tuple projections in each theorem |
| Tactic brittleness | Small generated changes explode proof scripts | Family lemmas, normalized IR, stable semantic interfaces |
| Nonlinear arithmetic | MULH/DIV proofs do not scale | Integer lemmas and staged decompositions, discovered with SMT but checked in Lean |
| Coverage drift | New opcode or selector has no theorem | Exact manifest-to-theorem coverage check |
| Pin drift | Proof silently moves to another Sail meaning | Generated receipts and byte-identical regeneration |

## 17. Definition of done

“Universal AIR → Sail refinement” is complete only when all of the following
hold:

- FV-1 through FV-5 in §15.1 each have named, kernel-checked exit evidence;
- the pinned Sail semantics are generated and normalized under a reviewed
  bridge for all 46 admitted selectors and the full generated step;
- the formal AIR is bound to the production evaluator at publication level;
- every accepted production AIR row implies, rather than is merely implied by,
  its exact generated-Sail retirement;
- every M31/Word32 conversion and integer lift is mechanically inventoried and
  proved injective/no-wrap over its admitted domain;
- all six fixed-table meanings are proved;
- admission/decode refinement is universal;
- every one of the 46 opcode IDs maps to one checked theorem;
- each theorem covers architectural output and emitted relation tuples;
- every opcode has a non-vacuity theorem;
- the opcode theorems compose across complete traces with the program,
  register, memory, clock, and public-boundary invariants;
- no exported theorem uses `sorry`, `admit`, or an undeclared axiom;
- required mutations demonstrate pipeline sensitivity;
- CI regenerates and kernel-checks everything from clean inputs;
- SA-1 premise 5 is updated to cite the exact theorem receipt; and
- the required non-author sign-offs are recorded and an independent party
  reproduces the result.

The completion receipt must fail closed unless it records all of:

- `normalized_retirements.proved = 46`;
- `publication_level.proved = 46`;
- `full_generated_sail_step = true`;
- `whole_frontend_verified = true`; and
- every required `external_signoffs` role as established.

It may still record `proof_system_soundness = false`; that field belongs to
the separate accepted-proof reduction in SA-1 premise 1.

Before that point, acceptable language is:

> “Level-1 normalized LUI/ADDI refinement pilot” or “memory/DIV stress
> mechanization.”

“N of 46 production opcodes machine-proved” is acceptable only after the
serialized-AIR and generated-Sail bindings are kernel checked for those N
opcodes. A digest-bound reviewed normalization is useful evidence, but it is
not counted as publication-level opcode coverage.

After that point, the precise claim is:

> “Every exact active row admitted by the shipped RV32IM AIR universally
> refines the pinned Sail transition under the explicit program, state, memory,
> range, and no-wrap premises.”

Even then, the project must not collapse the claim into “every accepted proof
is a correct Sail execution” until the independent proof-system validation and
reviewed PCS/FRI/Fiat–Shamir reduction close SA-1 premise 1.
