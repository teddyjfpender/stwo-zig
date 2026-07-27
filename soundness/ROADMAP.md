# RV32IM zkVM soundness roadmap

This roadmap tracks assurance beyond ordinary feature completeness. The
normative architectural model is pinned Sail RISC-V; Spike is an independent
executor, and the pinned RISC-V Architectural Tests provide the standards
corpus. Stark-V is retained only for legacy proof-layout lineage.

The two obligations stay separate:

1. **Semantic refinement:** every admitted retirement has the Sail-defined
   decode, state transition, memory effect, and next PC.
2. **Computational integrity:** an accepting proof forces that retirement
   sequence and its public program, input, output, roots, and completion state.

## Current assurance baseline — 2026-07-26

- [x] Exact Sail model, compiler, configuration, and transport patch are
      machine-pinned and reproducibly verified.
- [x] Exact Spike and architectural-test revisions are machine-pinned.
- [x] Canonical retirement comparison covers PC, word, register write, next PC,
      and memory effect with no PC normalization.
- [x] The deterministic positive/negative corpus passes live Sail and Spike
      comparison, including strict illegal/reserved/misaligned rejection.
- [x] All applicable upstream RV32I and RV32M architectural tests use
      Sail-generated signatures and pass the zkVM executor.
- [x] Every applicable architectural test follows execute → secure prove →
      separate-process verify in the formal audit.
- [x] MULH, MULHSU, and MULHU are admitted. Signed high multiplication binds
      both operand sign bits and the complete byte/carry recurrence.
- [x] MULH malicious-witness mutations are rejected at proof admission.
- [x] FENCE is admitted for the single-hart zkVM; FENCE.I remains an explicit,
      conservative profile exclusion.
- [x] Misaligned instruction targets and data accesses reject before state
      mutation and are constrained at the AIR boundary.
- [x] CPU/SIMD and Metal consume the same backend-neutral witness/AIR; Metal has
      no CPU fallback.
- [x] Completion is a public relation event, artifact schema v4 binds protocol
      and exact PCS geometry, and independent verification recomputes the
      decoded-program root from the supplied ELF.

The reproducible commands and evidence schemas live in
`scripts/riscv_formal_tools.py`, `scripts/riscv_trace_vectors.py`,
`scripts/riscv_arch_tests.py`, and `conformance/riscv/`.

## Closed under-constraints — 2026-07-26

Six demonstrated under-constraints in the opcode AIR were found by adversarial
review and closed. Each was inherited from the pinned Stark-V layout, so the
fixes are an intentional divergence recorded in `conformance/divergence-log.md`.

Every fix has a row-local rejection check. Five of the six have one in the
owning AIR module. The DIV divisor byte range does not: `semantics/div.zig`
covers only the quotient-sign and zero-divisor halves of that item, and the
divisor byte-range check lives in
`src/tests/riscv/divisor_byte_range_soundness_test.zig`. The committed-trace
coverage of all six, and what it does and does not establish, is the table
below.

- [x] Read-only accesses bind `next == previous`. Previously a source register's
      emitted bus value was a free prover choice that was also the operand the
      AIR computed on, so any register-reading instruction — a branch included —
      could rewrite the register file with an arbitrary word.
- [x] `SB`/`SH` preserve the unmarked bytes of the destination word.
- [x] `AUIPC` pins `imm_limbs[0] == 0`. Because `2^32 = 2p + 2`, every immediate
      previously admitted a second byte decomposition offset by `p + 2`.
- [x] `JALR` binds all source bytes, the signed I-immediate, bit 0, and the
      aligned target through an exact byte-carry recurrence. Its committed
      `target / 4` low20/high8 split mirrors the program AIR and enforces the
      successful-retirement address bound locally, including u32 wraparound.
- [x] `DIV`/`DIVU`/`REM`/`REMU` byte-range every divisor limb locally, bind the
      ambiguous zero-quotient sign while preserving the signed-overflow
      algebraic convention, and pin the zero-divisor convention. The
      proven-sufficient `lt_diff` RC_20 bound is unchanged.
- [x] `LB`/`LH` sign extension and `SRL`/`SRA` sign fill bind their sign
      witnesses to the operand bit they claim to represent.

The sweep's previously global DIV byte-ness and JALR target-bit obligations are
now row-local. No known residual obligation from that sweep rests solely on bus
closure or the consuming ROM row.

The review that found these is the reason the first item under "Continuing
adversarial work" is now the highest-priority soundness task rather than one of
several parallel ones: every one of the six was invisible to the Sail
differential (which validates the runner, not the AIR) and to the CP-11 oracle
(which compares against the layout that contains the same omissions).

## Committed-trace coverage of the six fixes — 2026-07-26

A row-local verdict says the AIR would reject a row. It does not say the row is
reachable through the committed pipeline, and "rejected" alone is not evidence
for the constraint under test. The seven modules below add the reachability half
where they can. The column that decides whether a test is a guard or merely
coverage is "attribution": an end-to-end case marked "no" still passes with its
fix deleted.

Every end-to-end entry means both halves — the guest proves and verifies
honestly, then the same guest with one committed row overridden does not.

**Why the attribution column is "row-local only" almost everywhere, and why that
is a harness limit rather than six oversights.** A `.main_row` override does not
reach the interaction trace or the lookup multiplicities.
`prover/main_trace.zig:116` derives multiplicity counters from the unmutated
`workspace.opcode_columns`, `:125` applies the override afterwards and only to
the duped committed main columns, and `prover/interaction_trace.zig:155` reads
the unmutated buffers too. So any override that moves a relation tuple leaves the
committed main trace disagreeing with the interaction trace, and proving raises
`ConstraintsNotSatisfied` whatever the AIR would have said. Every column the
read-only binding constrains is a bus tuple element, so no override can isolate
it end to end; `read_only_access_soundness_test.zig` pins this as an executable
control, and it is why `divisor_byte_range_soundness_test.zig`'s `.verification`
expectation is currently unsatisfiable. Until the hook feeds the overridden
columns into multiplicity ingestion and interaction generation, an end-to-end
rejection is evidence of reachability, not of which constraint did the rejecting.
Row-local attribution is unaffected and remains the load-bearing assertion.

| Closed item | Row-local check | End-to-end committed-trace test | Attribution asserted | Self-check reported |
| --- | --- | --- | --- | --- |
| Read-only `next == previous` | `semantics/{base_alu_imm,base_alu_reg,branch_eq,branch_lt,lt_imm,lt_reg,shifts_reg,load_store,div,mul,jalr}.zig`; `read_only_access_soundness_test.zig` | `read_only_access_soundness_test.zig`, `branch_eq` guest | row-local only | yes |
| `SB`/`SH` unmarked bytes | `semantics/load_store.zig`; `partial_store_soundness_test.zig` | `partial_store_soundness_test.zig`, `load_store` guest (`SB`, `SW`, `LW`) | row-local only | yes |
| `AUIPC` `imm_limbs[0] == 0` | `semantics/auipc.zig`; `auipc_alias_soundness_test.zig` | `auipc_alias_soundness_test.zig`, `auipc` guest | row-local only | yes |
| `JALR` target binding | `semantics/jalr.zig`; `jalr_target_soundness_test.zig` | `jalr_target_soundness_test.zig`, `jalr` guest, three forgeries | row-local, **and end-to-end for the bit-0 forgery** | yes |
| DIV divisor byte range | `divisor_byte_range_soundness_test.zig` only — **not** `semantics/div.zig` | `divisor_byte_range_soundness_test.zig`, `div` guest — honest half green, **forged half currently red** | row-local only | **no record** |
| `LB`/`LH`, `SRL`/`SRA` sign witnesses | `semantics/load_store.zig`, `semantics/shift_common.zig`; `load_sign_soundness_test.zig`, `shift_sign_soundness_test.zig` | `load_sign_soundness_test.zig` (`load_store` guest), `shift_sign_soundness_test.zig` (`shifts_reg` guest) | row-local only | yes |

The red DIV cell is a test-expectation failure, not an admitted forgery: that
test pins `RejectionStage.verification` and production refuses the row earlier
than the pin allows. No forged row anywhere in this sweep produced a proof.

"Self-check reported" means the module records an executed run with its real
output in which the specific constraint or lookup request was disabled, the
row-local attribution assertion failed because the forged row became admissible,
and the AIR file was then restored byte-for-byte. That is what makes the
row-local column a guard. Five of those six modules also report, unprompted,
that their end-to-end case still passes with the fix disabled; only
`jalr_target_soundness_test.zig`'s bit-0 case fails when its carry constraints
are deleted, and it is the only end-to-end guard in the sweep.

That asymmetry is a property of the test harness, not of the fixes.
`prover/orchestration.zig` duplicates the opcode witness columns, applies a test
row override to the duplicates it commits as tree 1, and then generates the
LogUp interaction trace from the unmutated workspace buffers. Any override of a
column that appears in a relation tuple therefore leaves the two trees
disagreeing, and the prover's own composition check refuses the row before a
proof exists, whatever the AIR says. Every fix above except the JALR bit-0
witness constrains a value that is also a bus tuple element, so no end-to-end
forgery of them can be attributed, and `RejectionStage.verification` in
`tests/riscv/committed_forgery_harness.zig` is unreachable for a `main_row`
override. Until the override runs ahead of interaction generation, these tests
establish reachability — an honest row of that family proves and verifies, and
the forged row never becomes a proof — and attribution stays row-local.

Several of those modules say in their own doc comments that nothing in the
repository previously proved a row of their family end to end. Read that as
"no test under `src/tests/riscv/` did", and not even that for `branch_eq` and
`load_store`: `prover_test.zig` already proves and verifies BEQ, BNE, `LW`, and
`SW` rows, and `scripts/riscv_arch_tests.py` already runs execute → prove →
separate-process verify over the pinned architectural corpus, which exercises
every one of the six families. What the honest halves add is a *guest the forged
half is derived from*, which is what keeps the rejection from being vacuous —
not first-ever coverage of the family.

## Continuing adversarial work

- [ ] Expand committed-witness mutation coverage to every opcode family. Eight
      of the seventeen families in `air/component_order.zig` now have a
      committed-trace forgery test: `mulh` (`mulh_soundness_test.zig`) and `lui`
      (one cell of one column, as the "lookup request" case in
      `main_witness_rejection_test.zig`) predate this work; `auipc`,
      `branch_eq`, `jalr`, `load_store`, and `shifts_reg` were added by the
      sweep above. All seven are green; `div`'s is red (below). Nine families
      have no committed-trace forgery test at all: `base_alu_imm`,
      `base_alu_reg`, `branch_lt`, `fence`, `jal`, `lt_imm`, `lt_reg`, `mul`,
      and `shifts_imm`.
      Within the covered families the coverage is one or two rows chosen to
      exhibit a specific bug, not the family's operand space: only the `is_sb`
      half of the partial-store gate is exercised, only `SRL`/`SRA` of
      `shifts_reg`, and only `LB`/`LH`/`SB`/`SW`/`LW` of `load_store`.
- [ ] Apply the committed-row override before `opcode_interaction.generate` in
      `prover/orchestration.zig` rather than after, so a row-locally coherent
      forgery reaches a real proof and loses the global LogUp closure at
      verification. Until then `RejectionStage.verification` in
      `tests/riscv/committed_forgery_harness.zig` is unreachable for a
      `main_row` override, that enum's doc comment overstates what a stage pin
      distinguishes, and no end-to-end test in this sweep can tell a constraint
      fix from a lookup fix.
- [ ] Give `src/tests/riscv/proof_admission_test.zig` the family enumeration its
      file name implies. It proves two hand-built traces — `base_alu_imm` and
      `mulh` — through a counting engine and verifies neither proof; the other
      fifteen families are not reached.
- [x] Commit a generic witness-rigidity suite over all seventeen families: every
      committed column must be observable through a constraint or a lookup, no
      opcode selector may be interchangeable with another whose semantics differ,
      and every access must emit a value determined by constrained inputs. The
      third property is what the six closed items above all violated. Its own
      bounds, as `witness_rigidity_test.zig` states them: a per-family row
      budget over the committed ELF corpus, an exhaustive sweep of the byte
      domain on the first honest row of each family and a fixed delta sweep
      elsewhere, so rigidity is decided over that domain and not over all of
      M31; and two
      `load_store` address columns are recorded as knowingly unobservable rather
      than the check being weakened around them.
- [ ] Repair the end-to-end non-byte DIVU divisor mutation (`[0, 0, 0, 256]`).
      The row-local half is done and green. The committed-trace half exists —
      `divisor_byte_range_soundness_test.zig`, "the honest DIVU proof verifies
      and the forged committed row does not" — and **currently fails**: it pins
      `RejectionStage.verification`, and for the harness reason above proving
      refuses the row first with `error.ConstraintsNotSatisfied`. Fixing the
      hook ordering is the repair that keeps the pin meaningful; relabelling the
      pin `.prover_constraints` makes the test green but leaves it asserting
      only reachability. The stale `TODO(soundness)` in
      `air/semantics/div.zig` still says the test is deferred and must be
      updated with whichever repair lands.
- [ ] Add a deliberately malicious prover harness for skipped instructions,
      stale reads, forged outputs, and altered completion.
- [ ] Exhaustively check small-limb component domains where enumeration is
      feasible, with Sail transitions as the reference relation.
- [ ] Maintain serialized-proof bit-flip, truncation, splice, and wrong-statement
      rejection corpora as the wire evolves.
- [ ] Increase deterministic differential generation beyond the current
      checked corpus and record seed ranges and retirement counts.

## Independent verification and accounting

- [x] Proof artifacts are serialized and accepted only by a separate verifier
      invocation bound to an externally supplied statement digest.
- [x] Statement mutation and malformed-proof tests cover the public artifact
      boundary.
- [ ] Add a second independently implemented verifier for the RISC-V proof
      protocol. Sail and Spike independently validate execution semantics, not
      the repository-specific PCS/FRI proof wire.
- [x] Publish the current conjectural security-bit accounting for every exposed
      PCS profile, explicitly separating it from a reviewed reduction.
- [ ] Obtain independent review of the FRI/list-decoding security accounting.
- [ ] Keep the Fiat–Shamir schedule and all domain-separated extensions in the
      conformance ledger with mutation coverage.

## Formal and external assurance

- [ ] Machine-check that AIR satisfaction refines the pinned Sail transition
      relation, beginning with instruction decode and memory consistency.
- [ ] Obtain independent AIR and protocol audits.
- [ ] Maintain a public bug-bounty scope for witness construction, statement
      binding, serialization, and verification.

Feature completion does not imply these longer-horizon audit items are done.
Conversely, they must not be represented as missing RV32IM instructions or as
authority for reintroducing a second semantic oracle.
