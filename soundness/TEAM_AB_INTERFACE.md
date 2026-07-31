# Team A / Team B interface reconciliation

> **Historical integration record — non-normative.** The contributor split in
> this document has no semantic meaning. Current claims and work sequencing
> live in
> [`RISCV_FRONTEND_VERIFICATION_STATUS.md`](RISCV_FRONTEND_VERIFICATION_STATUS.md).

This file records the exact conflict surface
between the two in-flight refinement branches, which side must win each
conflict and why, the guarantees a careless merge would silently drop, and the
integration order that preserves both sides' claims.

| Side | PR | Branch | Issue |
| --- | --- | --- | --- |
| Team A | #141 "formal: round-trip production LUI AIR through AIR IR v2" | `feat/issue-136-air-ir-v2` | #136 |
| Team B | #139 "Team B: generated Sail binding, LH/DIV stress, and 22-opcode rollout" | `feat/riscv-team-b-sail-binding-137` | #137 |

Both branches fork from the same merge base, `bddf3a7f`. Every git fact below
was computed against that base with `git diff --name-only main...<branch>` and
`git merge-tree --write-tree` between the two branch heads.

## 1. Real conflict surface

File-overlap intersection (4 files):

```
formal/riscv-refinement/RiscvRefinement.lean
formal/riscv-refinement/generated-manifest.json
scripts/riscv_refinement.py
scripts/tests/test_riscv_refinement.py
```

`git merge-tree --write-tree HEAD origin/feat/issue-136-air-ir-v2` reports
**two content conflicts**; the other two files auto-merge:

| File | Result |
| --- | --- |
| `scripts/riscv_refinement.py` | CONFLICT, 2 hunks |
| `formal/riscv-refinement/generated-manifest.json` | CONFLICT, 4 hunks |
| `formal/riscv-refinement/RiscvRefinement.lean` | auto-merges, but see 1.3 — the textual merge is semantically incomplete |
| `scripts/tests/test_riscv_refinement.py` | auto-merges cleanly; the 13 B-added and 4 A-added test names are disjoint |

Everything else is disjoint by construction: Team A touches `src/frontends/**`,
`build_support/**`, `RiscvRefinement/Air/{IR,Eval,Decode,Tests}.lean`,
`Field/**`, `Tables/**`, `riscv_refinement_lib/{air_program*,model,render}.py`;
Team B touches `RiscvRefinement/{Air/Family,Opcodes,Sail,Bridge,Arith}/**`,
`Common.lean`, `Memory.lean`, `Mutation.lean`, `AxiomAudit.lean`,
`lakefile.toml`, `riscv_team_b*.py`, `riscv_refinement_lib/sail*.py`, and the
Team B workflow. Neither branch edits a file in the other list.

### 1.1 `scripts/riscv_refinement.py` — 2 hunks

**Hunk 1 — the `AUDITED_THEOREMS` pinned tuple** (base lines 35–61, 26 names;
Team B lines 35–898, 862 names; Team A lines 35–70, 34 names).

Both sides extended the same tuple. B repinned it to all 862 theorems visible
under its widened `AxiomAudit.lean` filter (section 2.2). A appended 8 names
(`RiscvRefinement.M31.*` × 7 and
`RiscvRefinement.Air.FixedTableId.contains_eq_true_iff`) under the **old
narrow filter**, which reports only a fraction of declared theorems. Neither
side contains the other: B's 862 lack A's 8 new names; A's 34 share only the
26 base names with B and lack the other 836.

**Winner: neither side's literal text.** The tuple is machine-pinned. Take B's
862-name block during textual resolution (it preserves the wide-audit
property), then regenerate on the merged, rebuilt Lean environment:

```sh
python3 scripts/riscv_refinement.py audited-theorems --write
```

The regenerated tuple will be strictly larger than 862 + 8: under B's wide
filter the audit also reports every A theorem the old filter suppressed
(A's `Air/IR.lean`, `Air/Eval.lean`, `Air/Tests.lean`, `Field/M31.lean`,
`Tables/Fixed.lean`, `Air/Generated/LuiProgram.lean` declarations). A
hand-merged union is guaranteed wrong; only `--write` against the merged
environment is correct. The `verify`/receipt gate compares sets exactly, so CI
fails closed until this is done.

**Hunk 2 — `common_arguments` tail** (B lines 947–969: adds
`--reuse-committed-sail-evidence` plus the `reuses_committed_sail_evidence`
helper; A lines 104–107: adds `--air-program-ir-dir`).

**Winner: both.** The additions are orthogonal — B's flag rebuilds Sail
evidence from committed provenance without a live toolchain and refuses unless
byte-identical; A's flag routes the AIR IR v2 export directory. Keep B's
argument + helper *and* A's argument. Note A's `evidence()`/`prepared_outputs`
edits (`render.validate_air_program_export(paths.air_program_ir)`) land outside
the conflict markers and combine cleanly with B's `evidence()` rewrite; the
merged behavior must be confirmed by
`python3 -m unittest scripts.tests.test_riscv_refinement -v`.

### 1.2 `formal/riscv-refinement/generated-manifest.json` — 4 hunks

All four hunks are generated digests; the file's own header says it is
generator-owned. Per issue #137's cross-team contract, "Only the integration
DRI updates aggregate generated manifests and the final receipt."

| Hunk | Content | Winner |
| --- | --- | --- |
| ~line 11 | `canonical_digest` (three-way distinct) | regenerate |
| ~line 23 | `generators["scripts/riscv_refinement.py"]` sha | regenerate — the merged script differs from both parents |
| ~line 35 | `generators` shas for `render.py` (A changed), `sail.py` (B changed), `test_riscv_refinement.py` (both changed; merged file differs from both) | regenerate — no hand-merge can be right for the test file |
| ~line 266 | `proof_sources` shas: `RiscvRefinement.lean` (both changed), `AxiomAudit.lean` (B), `README.md` (A), plus A's new `Air/*.lean` entries | regenerate |

**Winner: neither.** Resolve by running the generator on the merged tree:

```sh
python3 scripts/riscv_refinement.py generate --reuse-committed-sail-evidence
python3 scripts/riscv_refinement.py check-generated --reuse-committed-sail-evidence
```

(or with a live pinned Sail toolchain; B's flag exists precisely so this
regeneration does not need one). The manifest's `proof_sources` also pins
`lakefile.toml` — both parents' committed manifests pin digests of files the
other side changed, so **any** take-one-side resolution is stale.

`formal/riscv-refinement/refinement-receipt.json` (A-only, no textual conflict)
pins `generated_manifest_digest = 14f3778a…`, A's manifest digest, and embeds
the audit's `theorem_axioms`. It goes stale the moment the manifest is
regenerated and the audit widens; the receipt must be re-minted after steps 6–7
of the checklist, not hand-edited.

### 1.3 `formal/riscv-refinement/RiscvRefinement.lean` — auto-merges, incompletely

B rewrote the root module (main's was a single `import RiscvRefinement.Coverage`)
to import **every** module explicitly, with a comment explaining why: Lake's
glob compiles unimported files, but the axiom audit walks the *environment*,
which contains only what the root transitively imports. A appended two imports
(`Air.Tests`, `Air.Generated.LuiProgram`) to main's one-liner. The auto-merge
yields B's full list plus A's two lines.

That merged root reaches most of A's new modules transitively
(`Air.Tests → Air → Air.Decode → Air.Eval → Air.IR → Tables.Fixed → Field.M31`)
— but **not** the umbrella modules `RiscvRefinement.Field` and
`RiscvRefinement.Tables`, which nothing imports. They would be compiled by the
glob and silently absent from the audited environment: exactly the gap B's
comment warns about. They are import-only today, so no theorem escapes *yet*,
but the fix is one line each. Post-merge, the root must explicitly list all of
A's modules: `Air`, `Air.IR`, `Air.Eval`, `Air.Decode`, `Air.Tests`,
`Air.Generated.LuiProgram`, `Field`, `Field.M31`, `Tables`, `Tables.Fixed`.
(Per branch policy, root-module imports are added centrally by the integration
DRI.)

## 2. Guarantees a careless merge would silently drop

### 2.1 `formal/riscv-refinement/lakefile.toml` — B's glob must survive

B changed the lib glob to
`globs = ["RiscvRefinement", "RiscvRefinement.+"]`. `"RiscvRefinement.+"`
matches **submodules only**; listing the root separately is what keeps the root
olean fresh. Before this fix the stale root made the axiom audit read an old
environment and report ~100 theorems instead of 862 (B commit `94c328bb`).

Team A's branch does **not** touch `lakefile.toml`, so git keeps B's version
automatically. The regression risk is a human "take theirs" during rebase or a
tooling checkout of A's file. Post-merge assertion:

```sh
grep -F 'globs = ["RiscvRefinement", "RiscvRefinement.+"]' formal/riscv-refinement/lakefile.toml
```

### 2.2 `RiscvRefinement/AxiomAudit.lean` — B's widened filter must survive

B removed the `ranges.range.pos != ranges.selectionRange.pos` condition that
quietly excluded most theorems (54 of 204 reported at the time) and now reports
every non-internal `RiscvRefinement.*` theorem with a declaration range — 862
on B's branch. A does not touch this file; git keeps B's version. Same
human-error risk as 2.1. Post-merge the audit count must **grow** (862 plus all
of A's newly visible theorems), never shrink; a count at or below 862 after
adding A's modules means the audit is reading a stale or under-imported
environment.

### 2.3 `scripts/riscv_refinement.py` — B's flags and the pinned tuple

Covered in 1.1. Both of B's additions (`--reuse-committed-sail-evidence`,
`audited-theorems` subcommand at line 1619 with its `--write`/check modes and
the `AUDITED_THEOREMS_BLOCK` repinning machinery) and A's `--air-program-ir-dir`
must all survive; the 862-name tuple must be regenerated, not merged.

### 2.4 `RiscvRefinement/Common.lean` — B's `Retirement` extension vs A's constructors

B extended the jointly versioned type:

```lean
structure Retirement where
  nextPc : Word
  write : Option RegisterWrite
  read : Option MemoryRead := none
  store : Option MemoryWrite := none
```

plus `MemoryRead`, `MemoryWrite`, `ByteMask`, `MemoryTuple`, and the
`Outcome` classification. A does not touch `Common.lean`, so the merge keeps
B's version. **Does A's Lean code construct `Retirement`?** Yes, in three
places (found with `git grep Retirement` on A's tree):

- `Air/Generated/Pilot.lean:82` `luiRetirement` and `:213` `addiRetirement`
  (A regenerated this file), both `Retirement where nextPc := …, write := …`;
- `Opcodes/{Lui,Addi}.lean` prove `…Retirement row = execute…` by
  `unfold … rw […]`;
- `Sail/Generated/Pilot.lean` (untouched by both branches) constructs the
  execute-side values the same two-field way.

Because B gave the new fields `:= none` defaults, all of A's two-field
constructions still elaborate, and the retirement-equality proofs still close:
after `unfold`, both sides are literal structure instances whose `read`/`store`
components are definitionally `none`. No A proof uses `Retirement.mk`,
anonymous-constructor, or arity-sensitive syntax (checked by grep). Expected
result: recompiles without edits — but this is the one interface where a
failure would be a *proof* failure, not a build failure, so the checklist
recompiles `Opcodes/{Lui,Addi}.lean` explicitly.

This extension is not a unilateral B move: issue #136 Stage A0 requires a
"Complete normalized `Retirement` interface agreed with Team B, including
optional memory read and masked memory write effects before LH work begins",
and issue #137 Stage B0 requires the "Complete normalized `Retirement` type
covering `next_pc`, optional register write, optional memory-read observation,
optional masked memory write, success/rejection classification, and no other
externally visible state change". B's `Retirement` + `Outcome` is that agreed
shape; A's contract (see 3.1) explicitly defers to it.

## 3. Interface questions

### 3.1 Does A's row-projection / `LocalRowEnv` shape match B's `*Environment` structures?

**There is no collision, because A has deliberately not frozen that layer.**
A's branch defines no `LocalRowEnv`; the name appears only in
`soundness/AIR_IR_V2_CONTRACT.md`, which says (section 8):

> This v2 object freezes the AIR-side carrier needed by the first LUI slice.
> It does not pretend to freeze the complete `Retirement`, `LocalRowEnv`, or
> final row/tuple theorem interfaces; section 13 records those joint
> follow-ups.

and (section 13):

> The complete normalized `Retirement` (including optional memory read and
> masked memory write), complete `LocalRowEnv`, final architectural
> row/relation-tuple theorem signatures, and their compatibility with generated
> Sail are deliberately not invented by this Team A document. They are jointly
> versioned Stage A0/B0 work with Team B under issue #137.

B's contract (`soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md`, section 8) states
the shape B built to:

> The row environment binds the AIR row to a `PreState`, an instruction word,
> and (for memory families) the pre-state memory word, exactly as
> `LuiEnvironment` and `AddiEnvironment` do today.

B's eight new `*Environment` structures
(`LoadStoreEnvironment`, `ShiftsImmEnvironment`, `ShiftsRegEnvironment`,
`MulEnvironment`, `MulhEnvironment`, `DivEnvironment`, plus the existing
`LuiEnvironment`/`AddiEnvironment`) follow exactly that pattern. A's IR v2
`projection` block operates one layer below — it names which *serialized
events* carry the architectural interface (`program_event`, one
`state_events` consume/emit pair, `source_events`, `destination_events`,
`next_pc` node) — and does not restate what row columns mean architecturally.
The two shapes are complementary today; the joint `LocalRowEnv` freeze is
future Stage A0/B0 work governed by issue #137's cross-team clause:

> `Retirement`, `LocalRowEnv`, row projections, tuple structures, and
> certificate schema are jointly versioned. Changes require both DRIs and
> replay of all already-counted opcodes.

### 3.2 Does A's IR v2 conflict with B's `MemoryTuple` or the access-clock ordinals?

**No — the ordinals agree exactly, definition for definition.** B's contract
section 8:

> Access clocks are `accessClock clock ordinal`, with the production ordinals:
> `.first = 4c-3`, `.second = 4c-2`, `.third = 4c-1`.

B's `Common.lean`: `accessClock clock ordinal = (clock - 1) * 4 + ordinal`, so
ordinals 1/2/3 give `4c-3`/`4c-2`/`4c-1`. B's family files use exactly
`accessClock row.clock 1|2|3` (rs1/rs2/rd in `Multiply.lean` and `Div.lean`;
base/operand-memory/destination in `Air/Family/LoadStore.lean` lines 372–380).

A's IR v2 carries a matching 1-based `access_ordinal` on lookup events
(`EvaluatedLookup.accessOrdinal : Option Nat` in `Air/Eval.lean`;
`access_ordinal` in `lookups/entry.zig`). A's `constraint_program.zig` tags
production events `accessChainAt/accessAt(…, 1|2|3)`: rs1=1, rs2=2, rd=3 for
`mul`/`mulh`/`div`, and rs1=1, memory-src=2, dst=3 for `load_store` — the same
assignment B proves against. B's `MemoryTuple { addr, clock, value }`
("`MemoryTuple.addr` is the aligned word bus address, matching the production
memory lookup argument") is a Lean-side relation tuple that A's v2 schema does
not define or contradict; A's metadata makes B's ordinal convention *checkable*
from the export rather than conflicting with it.

## 4. Decisive question: does A change what `riscv-refinement-ir` emits?

> **CORRECTION (measured, supersedes the analysis below).** The answer is
> **yes, for two of the seventeen families.** The reasoning in this section
> generalised from the two families A happens to commit (`lui`, `base_alu_imm`)
> to all seventeen; that generalisation is false.
>
> Both branches were exported and all seventeen families compared directly:
>
> | family | A's branch | main / #139 | |
> | --- | --- | --- | --- |
> | `shifts_imm` | `bfb3c405…3462` | `fe504838…3556` | **differs** |
> | `shifts_reg` | `415bdc6d…11a5` | `1508e095…ba150` | **differs** |
> | other 15 | — | — | identical |
>
> `columns` (names, order, roles) and the `constraints` array are **identical**
> on both sides; only the node table and six lookup numerators move, so the AIR
> still means the same thing — but the bytes differ and
> `shiftsImmIrDigest` / `shiftsRegIrDigest` break on merge.
>
> **Root cause.** `constraint_program.zig::constructFamily`'s `.full` branch
> initialises `active_row = activeExpression(...)` *before*
> `direct_constraints = directConstraints(...)`. For the shift families the
> active sum `is_sll + is_srl + is_sra` is therefore emitted into the symbolic
> recorder first, landing at nodes `[52] add(24,25)`, `[53] add(52,26)` instead
> of main's `[119]`, `[120]`. Columns 24/25/26 are `semantic_is_sll` /
> `semantic_is_srl` / `semantic_is_sra`. The other fifteen families are
> unaffected because their active expression is a single column or an
> already-memoised node, so nothing new is emitted.
>
> **Fix** (reported to Team A on PR #141): compute `direct_constraints` before
> `active_row` in that struct literal. Then all seventeen stay byte-identical
> and all six Team B digests survive untouched.
>
> The section's closing point still stands and is the reason this was caught:
> the confirming gate is mechanical, and a digest change is a loud failure
> rather than silent drift. Run `scripts/riscv_team_b.py check` on the merged
> tree regardless of what any analysis predicts.

The original provenance analysis follows. Evidence, not inference:

1. **Committed byte evidence.** A's branch commits regenerated
   `generated/air/{lui,addi}.json`. The diff against main changes exactly two
   values per file: `canonical_digest` and
   `production_binding.source_closure_sha256`. The third provenance field,
   `source_ir_sha256`, is **unchanged** (lui `044c5b95…`, addi `231d6e6b…`).
   Per `scripts/riscv_refinement_lib/air.py:650`, `source_ir_sha256` is
   `sha256_file(source_path)` — the hash of the **raw exported family JSON**
   consumed from the export directory. Identical hash = byte-identical raw
   export under A's refactored extractor, for both committed families.
   `source_closure_sha256` hashes the *extractor source file set*, which
   necessarily changed because A edited the extractor; it says nothing about
   output bytes.
2. **The serializer is untouched.** A does not modify
   `extract/json.zig`, `extract/symbolic.zig`, or
   `refinement_ir_export_test.zig` (empty diffs). The raw export contains only
   `family`, `modulus`, `notes`, `unmodelled_bus_requests`, `columns`
   (name+role), `nodes`, `constraints`, and `lookups`
   (label/domain/numerator/tuple) — no source-identity block, so the changed
   source closure cannot leak into the hashed bytes.
3. **The new metadata is not serialized.** A's `EventRole` and
   `access_ordinal` live on `entry.zig` entries and A's *new, separate* v2
   export. In `extract/model.zig` the serialized `Lookup` struct keeps exactly
   `label, domain, numerator, tuple`; roles only replace the old positional
   consume/emit classification, emitting the same `"consumed"`/`"emitted"`/
   `"request"` labels for well-formed pair sequences, and fail closed
   (`UnpairedBusRequest`) otherwise.
4. **Production and extraction share one path with pinned geometry.** A routes
   `semantic_eval.Eval` and `opcode_entries.Entries` through the single
   `constraint_program.Builder` (the Stage A1 "one typed `ConstraintProgram`"
   deliverable). The per-family entry counts are pinned unchanged by the
   existing test ("opcode lookup matrix preserves reviewed family geometry":
   `{18,16,20,16,14,11,9,11,7,12,18,8,16,16,22,25,3}`), and any
   reorder/content change would break the LogUp batching the shipped prover
   and its pinned vectors depend on.
5. **The build step is extended additively.**
   `build_support/products/riscv_refinement.zig` keeps
   `-Driscv-refinement-ir-dir` and the same uniqueness export; the v2 export
   runs beside it into a separate directory
   (`-Driscv-air-program-ir-dir`, default `zig-out/refinement-air-ir-v2`).
   B's workflow invocation
   `zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir`
   keeps working; it just also produces the v2 directory.

Residual risk, stated honestly: byte-identity is *committed* evidence only for
the `lui` and `base_alu_imm` families. For B's six digests
(`loadStoreIrDigest`, `shiftsImmIrDigest`, `shiftsRegIrDigest`, `mulIrDigest`,
`mulhIrDigest`, `divIrDigest` in `Air/Family/*.lean`) the confirming gate is
mechanical and already in CI: `scripts/riscv_team_b.py check` re-exports and
compares (`riscv_team_b.py:326 check_ir_digests`). If the refactor had altered
any of those six families, the failure mode is a **loud digest mismatch or a
fail-closed `UnpairedBusRequest`**, never a silent semantic drift. Run it once
on the merged tree before declaring the merge done (checklist step 8).

## 5. Team A's 24 opcodes

Complement of Team B's 22 certified opcodes (`team-b-coverage.json`: manifest
ids 2, 6, 7, 16–18, 19–26, 37–44) within the 46-entry
`src/frontends/riscv/opcode_manifest.zig`. Manifest id = position in the
manifest, cross-checked against A's own `Air/IR.lean` `Family.validOpcode`
table.

| Family | Opcodes (manifest id) | Count |
| --- | --- | ---: |
| `base_alu_reg` | ADD (0), SUB (1), XOR (5), OR (8), AND (9) | 5 |
| `base_alu_imm` | ADDI (10), XORI (13), ORI (14), ANDI (15) | 4 |
| `lt_reg` | SLT (3), SLTU (4) | 2 |
| `lt_imm` | SLTI (11), SLTIU (12) | 2 |
| `branch_eq` | BEQ (27), BNE (28) | 2 |
| `branch_lt` | BLT (29), BGE (30), BLTU (31), BGEU (32) | 4 |
| `jal` | JAL (33) | 1 |
| `jalr` | JALR (34) | 1 |
| `lui` | LUI (35) | 1 |
| `auipc` | AUIPC (36) | 1 |
| `fence` | FENCE (45) | 1 |
| **Total** | | **24** |

This matches issue #136 Stage A4's table exactly (24 = 5+4+2+2+2+4+1+1+1+1+1),
and 24 + 22 = 46 with no overlap and no gap.

## 6. Merge order and integration checklist

**Recommended order: merge Team B (#139) first, then rebase Team A (#141) on
the result.** Rationale: the guarantees a careless merge would silently drop
(sections 2.1–2.3) are all B's; landing B first makes them the protected
baseline, so A's rebase surfaces every remaining decision as an explicit
conflict A must resolve consciously. The reverse order would leave B rebasing
its wide-audit machinery over A's stale 34-name pin — the exact silent-loss
shape this document exists to prevent. Additionally, A's post-merge
regeneration needs B's `--reuse-committed-sail-evidence` to rebuild the
manifest without a live Sail toolchain.

Checklist for the #141 rebase/integration (integration DRI):

1. Merge #139 into `main` unchanged.
2. Rebase #141. In `scripts/riscv_refinement.py`:
   - hunk 1: take B's 862-name `AUDITED_THEOREMS` block verbatim as the
     transient state (regenerated in step 6);
   - hunk 2: keep **both** B's `--reuse-committed-sail-evidence` + helper and
     A's `--air-program-ir-dir`.
3. In `formal/riscv-refinement/RiscvRefinement.lean`: keep B's full explicit
   import list, add all ten A modules explicitly — `Air`, `Air.IR`,
   `Air.Eval`, `Air.Decode`, `Air.Tests`, `Air.Generated.LuiProgram`, `Field`,
   `Field.M31`, `Tables`, `Tables.Fixed` (the auto-merge omits `Field` and
   `Tables` from the environment entirely; see 1.3).
4. Assert B's guarantees survived (they should, untouched by A):
   `lakefile.toml` glob line (2.1) and the widened `AxiomAudit.lean` filter
   (2.2).
5. Build the merged Lean tree (`lake build` in `formal/riscv-refinement`), and
   explicitly recompile `RiscvRefinement/Opcodes/{Lui,Addi}.lean` to confirm
   A's `Retirement` equality proofs close over B's extended type (2.4).
6. Regenerate the audited-theorem pin:
   `python3 scripts/riscv_refinement.py audited-theorems --write`. Sanity:
   count strictly greater than 862; every name in both parents' tuples present.
7. Regenerate `generated-manifest.json`
   (`generate` / `check-generated`, with `--reuse-committed-sail-evidence` or a
   live pinned Sail toolchain), then re-mint `refinement-receipt.json` via the
   `receipt` flow. Both are DRI-only artifacts per issue #137.
8. Confirm the Team B digest gate on the merged tree (expected green per
   section 4):
   ```sh
   zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir
   python3 scripts/riscv_team_b.py check --air-ir-dir zig-out/team-b-ir
   python3 scripts/riscv_team_b_witnesses.py --air-ir-dir zig-out/team-b-ir
   ```
   If any of the six digests mismatches, the AIR bytes changed after all: stop,
   diff the fresh export against the capsule's recorded family, and re-pin only
   with sign-off from both DRIs (jointly versioned surface).
9. Run the Python suites:
   `python3 -m unittest scripts.tests.test_riscv_refinement scripts.tests.test_riscv_team_b scripts.tests.test_riscv_team_b_witnesses scripts.tests.test_sail_translation scripts.tests.test_sail_air_composition_contract -v`.
10. Re-run the merged CI workflows (`riscv-refinement.yml` and A's AIR
    IR gates); note B's workflow now also builds the v2 export inside
    `riscv-refinement-ir` (additive, slower, harmless).
11. Do not re-freeze interfaces in this merge: `Retirement` is now the agreed
    Stage A0/B0 shape; `LocalRowEnv` and the final row/tuple theorem
    signatures remain open joint work under issue #137's jointly versioned
    clause. Any future change to them requires both DRIs and replay of all
    already-counted opcodes.

## 7. External formal evidence: StarkWare's Lean 4 Stwo proofs

<https://github.com/starkware-libs/formal-proofs> (Apache-2.0, same licence as
this repository) contains a Lean 4 verification of Stwo. Most of it is
Cairo-specific — `Semantics/` is the Cairo VM and `AirInfra/Airs/` is `Casm` and
`Felt252Utils`, neither reusable for the RISC-V frontend. But `Lookups/` is
frontend-agnostic, and one result there lands directly on a premise this
repository currently records as open.

### What it proves

`Stwo/Verification/Lookups/Logup.lean:1606`,
`equal_count_of_multiplicity_one''`, concludes

```
Multiset.count x (yield_i.toList.map f) = Multiset.count x (use_i.toList.map f)
```

from the LogUp cumulative-sum constraint (`cumulativeC`), given
`h_z : z ∉ exceptionalSet f m pr` and both side cardinalities below
`ringChar F`. That is multiplicity-wise equality between the yield and use
sides — i.e. the reduction from a sampled LogUp equality to exact tuple-wise
equality that [`SAIL_AIR_COMPOSITION.md`](SAIL_AIR_COMPOSITION.md) records as
**not discharged by CR-1**.

### What it does not do

It does **not** eliminate the randomized-soundness assumption.
`h_z : z ∉ exceptionalSet` *is* that assumption — made precise and quantified
rather than removed. Anyone citing this result must carry that hypothesis
forward; the honest statement is "the reduction is proved conditional on the
challenge avoiding an explicit exceptional set", not "LogUp soundness is
closed".

It is also stated over a general `[Fintype F] [Field F]`, so instantiating it at
this repository's field and lookup encoding is real work, not a rename.

### Why this matters more than it looks

The `mul` AIR has **no constraint root for the multiplication** — all 22 roots
are booleanity, selector, register-copy and destination plumbing, and the
product identity is carried entirely by the four `range_check_8_11` requests
(see the O1 bridge result, `RiscvRefinement/Air/Bridge/`). For the multiply and
divide families, lookup soundness is not background scaffolding; it is what
holds the arithmetic. A premise that is merely assumed there is load-bearing in
a way it is not for, say, LUI.

### Adoption plan

Three options were considered. The decision is **(2), with (3) as the immediate
step**:

1. **Take Mathlib into `formal/riscv-refinement`.** Rejected. The project
   deliberately has `"packages": []` — `lake build` is offline, the external TCB
   is empty, and the CI leg is cheap because of it. Their project needs Mathlib
   on Lean **4.23.0-rc2**; this one pins **4.29.0**.
2. **A separate Lean component importing the result behind a narrow
   interface**, leaving the refinement project dependency-free. This is the
   target. It confines Mathlib and the toolchain difference to one component
   whose only export is the instantiated reduction.
3. **Cite it as external evidence without importing.** Done now, so the
   documentation stops implying nobody has proved this. Section CR-1 of
   `SAIL_AIR_COMPOSITION.md` carries the citation and the caveat.

Sequencing: (3) is landed with this document. (2) should not start until the
#139/#141 merge settles — it adds a second Lean toolchain to the repository and
that is not a change to make while two large formal PRs are converging.

## 8. Measured impact of #143 (Team A rollout head a1d3e277) — 2026-07-29

Full report: `/tmp/f2-pr143-impact.md`. Method: detached worktrees of #141
(9d86a203), #142 (2188336d) and #143 (a1d3e277), `zig build
riscv-refinement-ir` in each, byte-diff of all 17 family JSONs against
`zig-out/team-b-ir` on #139 (whose bytes were first re-verified against all six
`*IrDigest` pins). Nothing below is inferred from diffs.

### 8.1 Results

- **#143 vs #139 baseline: 16/17 families byte-identical.** Only `load_store`
  differs, and the difference is exactly the issue #140 fix: one inserted
  constraint `enabler * rs1_next_3 = 0` (new node 280 `mul(63,21)`, constraint
  index 69, 78→79 constraints, uniform +1 renumber of node ids ≥ 280). Columns,
  lookup order/labels/domains/tuples, and `unmodelled_bus_requests` unchanged.
- **#143's `load_store.zig` is byte-identical to #142's**, and a #142-worktree
  export is byte-identical to the #143 export for all 17 families. New
  `load_store` digest under either:
  `cadb1b662ec30864615aa84541c1bcd863e921f306446ea1c7a328c650180b20`.
- **#141 head as-is renumbers FOUR families, not two**: `lt_imm`, `lt_reg`,
  `shifts_imm`, `shifts_reg` (the section-4 assessment undercounted).
  Renumbering-only: constraint and lookup expression trees are equal in order
  for all four. #143 commit c65febe2 carries the `constructFamily` reorder
  (direct constraints before `active_row`) and restores byte identity for all
  four; #141's head does not have it.
- `expectedArity` unchanged; the new `EventRole`/`access_ordinal` fields in
  `lookups/entry.zig` are construction metadata that never reach the
  team-b-ir JSON; the 46 `*.air-ir-v2.json` artifacts are a parallel format,
  not a change to the family export.

### 8.2 Digest and proof cost to Team B

Exactly one of the six pins breaks: `loadStoreIrDigest` → `cadb1b66...`, plus a
one-constraint extension of the LoadStore transcription (cited indices ≥ C69
shift by one). That bill belongs to #140/#142 and is paid once; #143 adds zero
cost on top. `divIrDigest`, `mulIrDigest`, `mulhIrDigest`, `shiftsImmIrDigest`,
`shiftsRegIrDigest` survive byte-identical.

### 8.3 Merge order (supersedes section 6 where they disagree)

**#139 → #142 → (#141 + #143 as one unit).** #139 touches no `src/`, so zero
re-derivation. #142 triggers the single owed load_store re-pin. The A stack
then lands measured-export-neutral. **#141 must never sit merged alone** — it
breaks both shift pins and silently renumbers `lt_imm`/`lt_reg`.

Conflict caution: #143 vendors STALE Team B snapshots — `DecodeTeamB.lean`
from #139 commit a3622076 (31 commits behind), `Memory.lean`/`Common.lean` from
3bbd3eab. #139's versions are strict name-supersets (adds `isRType_fields`,
`isShiftImm_fields`, `isLoad_fields`, `isStore_fields`, `address_split`,
`byteOffset_split`, `signExtendByte_fill`, `signExtendHalf_fill`,
`WordBytes.word_halves`). On every conflict in those three files, **take
#139's version**; regenerate (never hand-merge) `generated-manifest.json`,
`refinement-receipt.json` and `Generated/Pilot.lean`; root imports in
`RiscvRefinement.lean` are merged centrally by the integration monitor.
