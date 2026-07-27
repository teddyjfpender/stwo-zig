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

**What the end-to-end stage now distinguishes, and what it still cannot.** The
committed-row override is applied to `workspace.opcode_columns` before
`lookup_sources.ingest`, so the multiplicity counters, the interaction trace and
the committed main trace are all derived from the forged witness. A forged row is
therefore refused by the AIR or by the LogUp closure, and no longer by the prover
disagreeing with itself. The stage pin became meaningful as a result: a fix that
lives in a direct constraint stops the row before a proof exists
(`.prover_constraints`), and a fix that lives in a lookup request lets the row
prove and loses the global sum (`.verification`). Deleting the fix moves the
stage, so the pin is now a real discriminator between the two kinds of fix.

It is still not full attribution for most of the six. The end-to-end stage says
*which half of the pipeline* rejects, not *which relation*: five of the six
forgeries also move a `memory_access` tuple element, so the global memory
argument would reject them even with the fix deleted. Only a forgery that moves
no bus can attribute end to end — `jalr_target_soundness_test.zig`'s bit-0 case
(`.prover_constraints`) and `bitwise_result_soundness_test.zig`
(`.verification`), which is why the latter exists. Row-local attribution remains
the load-bearing assertion everywhere else.

A modelling choice this rests on, recorded because it points one way. A forged
row whose lookup tuple is not in its table cannot be ingested by the honest
prover: there is no multiplicity row to increment.
`source_ingest.UnrepresentableRequest` lets the harness model the adversary that
hand-builds its multiplicity column and simply omits the impossible request; the
omitted fraction is what makes the global sum non-zero. Production still rejects
such a request as the prover bug it would be. So a `.verification` verdict is a
statement about the strongest adversary, not about the honest pipeline aborting.

| Closed item | Row-local check | End-to-end committed-trace test | Stage | Attribution asserted | Self-check reported |
| --- | --- | --- | --- | --- | --- |
| Read-only `next == previous` | `semantics/{base_alu_imm,base_alu_reg,branch_eq,branch_lt,lt_imm,lt_reg,shifts_reg,load_store,div,mul,jalr}.zig`; `read_only_access_soundness_test.zig` | `read_only_access_soundness_test.zig`, `branch_eq` guest | `.prover_constraints`; the bus-only control reaches `.verification` | row-local only | yes |
| `SB`/`SH` unmarked bytes | `semantics/load_store.zig`; `partial_store_soundness_test.zig` | `partial_store_soundness_test.zig`, `load_store` guest (`SB`, `SW`, `LW`) | `.prover_constraints` | row-local only | yes |
| `AUIPC` `imm_limbs[0] == 0` | `semantics/auipc.zig`; `auipc_alias_soundness_test.zig` | `auipc_alias_soundness_test.zig`, `auipc` guest | `.prover_constraints` | row-local only | yes |
| `JALR` target binding | `semantics/jalr.zig`; `jalr_target_soundness_test.zig` | `jalr_target_soundness_test.zig`, `jalr` guest, three forgeries | `.verification` for the two range-check forgeries, `.prover_constraints` for bit 0 | row-local, **and end-to-end for the bit-0 forgery** | yes |
| DIV divisor byte range | `divisor_byte_range_soundness_test.zig` only — **not** `semantics/div.zig` | `divisor_byte_range_soundness_test.zig`, `div` guest — both halves green | `.verification` | row-local only | **no record** |
| `LB`/`LH`, `SRL`/`SRA` sign witnesses | `semantics/load_store.zig`, `semantics/shift_common.zig`; `load_sign_soundness_test.zig`, `shift_sign_soundness_test.zig` | `load_sign_soundness_test.zig` (`load_store` guest), `shift_sign_soundness_test.zig` (`shifts_reg` guest) | `.verification`, except the `SRL` direct constraint at `.prover_constraints` | row-local only | yes |

No forged row anywhere in this sweep produced a proof that verified. The rows now
pinned at `.verification` do produce a proof, which is the point: they are the
forgeries whose only guard is a preprocessed lookup, and a proof that fails the
global LogUp closure is exactly the shape that fix has.

"Self-check reported" means the module records an executed run with its real
output in which the specific constraint or lookup request was disabled, the
row-local attribution assertion failed because the forged row became admissible,
and the AIR file was then restored byte-for-byte. That is what makes the
row-local column a guard. Five of those six modules also report, unprompted,
that their end-to-end case still passes with the fix disabled; only
`jalr_target_soundness_test.zig`'s bit-0 case fails when its carry constraints
are deleted, and it is the only end-to-end guard in the sweep.

That "still passes with the fix disabled" asymmetry has not been re-measured
since the harness fix and should not be assumed to survive it: those runs were
recorded when every `.main_row` forgery was refused by the prover disagreeing
with itself, which is a rejection no fix can influence. Each affected module's
self-check needs re-running before its end-to-end line can be read as a guard.

What has changed is that the stage is now decided by the AIR. Every fix above
except the JALR bit-0 witness constrains a value that is also a bus tuple
element, so the *relation* that rejects still cannot be isolated end to end and
attribution stays row-local. But `.verification` is reachable, so the tests now
separate a constraint fix from a lookup fix, and
`bitwise_result_soundness_test.zig` shows the remaining gap is about bus
overlap and not about the harness: its forgery moves no bus, and its end-to-end
rejection is attributable to one preprocessed table.

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

- [ ] Expand committed-witness mutation coverage to every opcode family. Nine
      of the seventeen families in `air/component_order.zig` now have a
      committed-trace forgery test: `mulh` (`mulh_soundness_test.zig`) and `lui`
      (one cell of one column, as the "lookup request" case in
      `main_witness_rejection_test.zig`) predate this work; `auipc`,
      `branch_eq`, `div`, `jalr`, `load_store`, and `shifts_reg` were added by
      the sweep above, and `base_alu_reg` by
      `bitwise_result_soundness_test.zig`. All nine are green. Eight families
      have no committed-trace forgery test at all: `base_alu_imm`,
      `branch_lt`, `fence`, `jal`, `lt_imm`, `lt_reg`, `mul`, and
      `shifts_imm`.
      Within the covered families the coverage is one or two rows chosen to
      exhibit a specific bug, not the family's operand space: only the `is_sb`
      half of the partial-store gate is exercised, only `SRL`/`SRA` of
      `shifts_reg`, and only `LB`/`LH`/`SB`/`SW`/`LW` of `load_store`.
- [x] Apply the committed-row override before multiplicity ingestion and
      interaction generation, so a row-locally coherent forgery reaches a real
      proof and loses the global LogUp closure at verification.
      `prover/test_witness_hook.applyOpcodeWitness` writes into
      `workspace.opcode_columns` ahead of `lookup_sources.ingest`; `.main` keeps
      its post-generation single-cell semantics and the two are documented apart
      at the hook. Seven end-to-end expectations moved from
      `.prover_constraints` to `.verification` as a result.
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
- [x] Repair the end-to-end non-byte DIVU divisor mutation (`[0, 0, 0, 256]`).
      Both halves of `divisor_byte_range_soundness_test.zig` are green with the
      `.verification` pin intact: the hook fix above is what made that pin
      satisfiable rather than the pin being relabelled. The stale
      `TODO(soundness)` in `air/semantics/div.zig` is replaced by a pointer to
      the test. The DIV divisor byte range still has no row-local check in
      `semantics/div.zig` itself and no recorded adversarial self-check.
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
      the repository-specific PCS/FRI proof wire. Nothing below closes this
      item: no second implementation reads a proof.

      One slice of it now exists, named for what it is.
      `scripts/air_satisfaction.py` is an independent AIR **row-satisfaction and
      LogUp-closure checker**. It is not a verifier and must not be cited as
      one. It reads a committed opcode trace exported from a real proving run
      (`src/tests/riscv/committed_trace_export_test.zig`, via the test-only
      `prover/test_trace_dump.zig`) together with the extracted per-family IR,
      and re-decides in Python, sharing no code with the Zig evaluator:

        * the committed-row placement permutation — the export is in committed
          circle-domain order and the reader inverts it itself;
        * every direct constraint of every real opcode row, over M31;
        * every activated preprocessed-table request: the box tables and the
          functional `bitwise` table;
        * every opcode component's claimed LogUp sum, recomputed from the
          committed trace and the exported challenges rather than read from the
          prover;
        * the verifier's public boundary compensation, as a second
          implementation of `air/public_logup.zig`;
        * the global cancellation of opcode claims + infrastructure claims +
          boundary.

      On the honest export that is 10 real rows across four families, 394
      direct constraints, 44 box requests, 4 `bitwise` requests, four
      recomputed claims all agreeing with the prover's, and a zero global sum.

      What it does not touch is what this item still asks for. The proof wire —
      PCS commitments, Merkle openings, FRI, the composition polynomial, OODS,
      the Fiat–Shamir transcript — is never read; nothing in the checker opens
      a proof. Three further limits are load-bearing and are stated at the tool
      itself: the export is bound to the commitment by a code-level identity
      (`copyOpcodeColumns` duplicates the exported buffers verbatim into the
      committed array) and not a cryptographic one, so the checker cannot tell
      that the values it read are the values the proof opens; infrastructure
      claims (program, RW memory, Merkle, Poseidon2, clock update, the six
      tables) are taken as given, so a closure failure attributes no further
      than "the opcode side and the boundary agree, the ledger does not"; and
      padding rows are out of scope, because the extracted IR fixes the
      preprocessed `is_active` selector to one.

      It is shown failing, which is the only reason a green run means anything.
      Two of the three exports are forgeries and the checker attributes each to
      the right layer: the `bitwise_result_soundness_test.zig` forgery, whose
      only guard is a preprocessed table, produces exactly one LOOKUP violation
      (`1 xor 15 = 14, the row claims 15`) with every direct constraint still
      vanishing; a raised `ADDI` destination limb produces exactly one
      CONSTRAINT violation in `base_alu_imm`. Both lose the global sum.
      `scripts/tests/test_air_satisfaction.py` pins all of that, anchors the
      QM31 tower and the boundary reimplementation to the Rust-oracle vector
      pinned in `air/public_logup.zig`, and records an executed self-check in
      which the placement permutation was replaced by a plain bit reversal: the
      honest export then failed with four constraint violations while the
      global sum stayed zero, because the closure check sums over the domain
      and is invariant under any permutation of the rows.
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
