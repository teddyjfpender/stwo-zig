# Recursion qualification delivery plan

**Status date:** 2026-10-19

**Governs:** delivery of `recursion_qualified = true` for the Poseidon2
recursive RISC-V lane under
[`soundness/RISCV_RECURSION_SOUNDNESS_CONTRACT.md`](../../../soundness/RISCV_RECURSION_SOUNDNESS_CONTRACT.md).
The contract defines what "sound" means (requirements S/T/C/P/K/V, gates
G-1 to G-10, work items W-1 to W-9). This plan defines the order, ownership,
exit criteria and working rules that get the lane there without repeating the
roadblocks of September and October.

**Baseline:** PR #303 (`feature/riscv-recursion-audit-realignment`, head
`cb9c11309`). It delivers: the detached leaf rebuilds its complete Tree 0 from
its pinned key with no proof loaded, verified for 15 fresh q193 leaf keys
across the 1/2/4/8-leaf setups
(`vectors/reports/riscv-recursion-20261019/leaf-tree0-key-only/README.md`);
parent admission rejects a swapped child-key pin before reading either child
proof; selected V2 physical claims are bound across transcript and
composition; the scheduled leaf Tree 0 is pinned in the row-five
preprocessing. It does not deliver qualification, and the PR says so.

## 1. Where the roadblocks came from

Each of these happened at least once in the last two months and each is
addressed by a rule in section 3.

| Roadblock | What it cost | Root cause |
| --- | --- | --- |
| Leaf path completed before the parent-key design gap was confronted | Weeks of leaf work that cannot flip the ledger; a late discovery that `KeyV1` (`src/frontends/riscv/recursion/detached_parent_protocol_v1.zig:46-54`) carries child-key hashes, geometry, parameters and a claimed root but no recipe from which the parent's fixed circuit can be rebuilt without child proof captures (`detached_parent_preparation_v1.zig:65-80` builds it through verified captures) | Critical path was not identified before work started; the contract's G-8(c) names the obligation but the schema change it implies was not scheduled first |
| Identity-bearing changes landed piecemeal | Every change to the native AIR or transcript invalidated every key, bundle and pin; stale `child-0-key.json`, `InvalidCatalogGeometry`, build breaks from 7-versus-9 constraint counts, skipped tests | No rule that identity changes land as one batch before any artifact is regenerated |
| Concurrent edits to shared files | Transient `MerkleTypedGeometryMismatch`, undeclared-identifier compile errors, wasted full-suite runs | No file ownership per workstream; full suites run during active edits |
| Progress reported as "nearly qualified" | Trust cost; re-planning | No shared vocabulary for status; gate records not required for claims |
| Hostile controls deferred | G-8(a) still open: nobody has a prover that re-proves consistently after replacing Tree 0 | The negative control needs a test-only prover hook, which was never designed as a deliverable |
| Pre-contract migration tooling kept alive | Confusion about which keys are valid | Decided 2026-10-18 (W-5): retired, fail closed |

## 2. Definition of done

Done means every gate G-1 to G-10 has a retained, reproducible passing record
at one source revision, section 11 of the contract has been applied, and the
ledger reads `recursion_qualified = true` for that revision. Nothing short of
this is "qualified". Intermediate states use the vocabulary in section 6.

## 3. Working rules

1. **Critical path first.** Work that changes an identity (plan or shape id,
   circuit id, provider authority digest, catalog identity, leaf or parent key
   schema) is the critical path. It is designed, reviewed and landed before
   any gate test is pinned and before any artifact is regenerated. Nothing
   downstream of an identity is touched until the identity batch is merged.
2. **One identity batch.** W-1, W-2, W-3, W-4, W-9 and the parent key schema
   (section 4, Phase 1) land in one PR. A partial identity change is not
   merged. The batch may be developed in parallel branches by file ownership
   but is merged, pinned and tagged once.
3. **Keys are recipes, proofs are evidence.** A key must contain everything
   needed to rebuild the node's fixed circuit and Tree 0 with no proof loaded
   (contract K-8). A key that needs a proof capture to reconstruct its own
   fixed rows is a bug in the schema, not a gap to paper over with a root
   comparison. Comparing a captured root to a pinned root is an evidence
   check, not reconstruction.
4. **Gates before regeneration.** The gate tests (W-7) are written against the
   new identities before the regeneration runbook (W-6) runs, so artifacts are
   generated once, against passing gates. Regeneration is the last expensive
   step, not the first.
5. **Ownership per workstream.** Each workstream in section 5 owns a disjoint
   file set. A change outside the owned set goes through the owner. Full
   suites run only at batch boundaries by the integrator; developers run
   focused steps (`zig build -l | grep test-` in `src/frontends/riscv` and
   `src/integrations/riscv_cpu`).
6. **No new skips.** `STWO_RECURSION_RUN_UNQUALIFIED_LANE` is the only
   permitted skip and it is removed in Phase 4. A test that cannot pass is
   fixed or deleted with a reason, not gated.
7. **Pins are generated, never typed.** Every digest, count and root pin is
   produced by a script or a focused test's printed value and recorded with
   the command that produced it. The pre-October q193 key stays committed as
   the G-4 negative control.
8. **Status vocabulary** (section 6) is mandatory in PR descriptions, commit
   messages and the ledger. "Qualified" may appear only in a Phase 4 PR that
   carries the gate records.

## 4. Phases and exit criteria

### Phase 0: design freeze (critical path)

Deliverables are documents and signatures, not code. Each is a section added
to the contract or to this plan and reviewed by someone other than its author.

- **P0-1 Parent key schema (new K-9).** Specify what `KeyV1` must carry so that
  `prepareParents` can be executed from the key and the two child keys alone:
  the two child key identities and their Tree 0 roots (already present as
  `child_key_sha256` and the leaf keys' new Tree 0 field), the publication
  mode, cohort parameters, the fixed-row family recipes the parent circuit is
  built from (the same families PR #303 regenerates for the leaf:
  transcript, public relay, public control, PCS fixed row, FRI and trace
  Merkle fixed rows, boundary fixed rows) with their shape and schedule ids,
  and the parent's own Tree 0 root. Define `rebuildFixedFromKey(parent_key,
  child_keys)` as the only path that produces the parent's Tree 0 at
  admission; `preprocessed_root` becomes an output of that function, checked
  against the pinned value, never an input. Acceptance: the schema is written
  with field types and the identity hash order; the reconstruction function is
  named with its error set; G-8(b) and G-8(c) are restated against it.
- **P0-2 Hostile re-proven control (G-8(a)) design.** Specify a test-only
  native prover hook that replaces the Tree 0 commitment with the root of a
  prover-generated preprocessed tree (one extra `is_active` row, or one
  altered lookup tuple) and then re-proves every later stage consistently, so
  the only defect in the proof is the tree. State where the hook lives
  (beside `src/tests/riscv/malicious_prover_harness.zig`), how it is kept out
  of product binaries (test module import only), and the expected standalone
  leaf verifier error. Acceptance: the design names the hook, its guard and
  the error.
- **P0-3 Equivalence oracle design (G-1, G-2).** Specify the recording wrapper
  that drives the native verifier through the scheduled channel and the
  sampled-point comparison against `evalCompositionPolynomialAtPoint`,
  including the random-seed protocol (at least 64 seeds) and what is printed on
  mismatch (first differing frame or constraint index). Acceptance: test file
  names, inputs and pass criteria are fixed before Phase 1 starts.
- **P0-4 Identity inventory.** List every digest, count and pin that Phase 1
  will move (contract K-7), the script or test that regenerates each, and the
  order. Acceptance: the list is complete against `grep` of the current pins;
  each entry has a regeneration command.

Exit: all four reviewed and merged as documentation. Expected effort: three
to five working days for one engineer plus one reviewer. Do not start Phase 1
coding before P0-1 is signed; it changes the parent key hash order and
everything downstream.

### Phase 1: the identity batch

One PR. Parallel development by file ownership (section 5); single merge.

| Item | Contract | Owner set | Exit check |
| --- | --- | --- | --- |
| W-1 physical claims in the scheduled transcript | T-4, T-5, C-5 | transcript | `payloadWordCount` returns the T-4 frame; both `@hasDecl` bypasses removed; plan and shape ids re-pinned |
| W-2 boundary AIR with root inputs | C-2, C-3 | composition | builder no longer returns `InvalidComponentOrder`; memory component contributes 9 constraints; circuit id re-pinned |
| W-3 frozen leaf geometry | K-6 | leaf | constants re-derived from the hardened statement by `src/tools/riscv/recursive_csp_shape_inspector`; `validateStatement` called before transcript binding |
| W-4 provider mode pin | P-2, P-6 | provider | `enabler·(1 − io) = 0` in the universal and compact shells; authority digest and manifests re-sealed |
| W-9 leaf Tree 0 as key constant | V-14, K-8 | leaf | landed in PR #303 for the leaf; confirm `constant_mask = 1` in both row-five sources |
| P0-1 parent key schema | K-9 (new) | parent | `rebuildFixedFromKey` implemented; `prepareParents` no longer requires child captures to produce Tree 0; parent key identity re-pinned |
| W-5 migration retirement | K-4 | tooling | tools fail closed (done 2026-10-18); confirm no caller |

Exit: `zig build test-riscv -Doptimize=ReleaseSafe` and `test-riscv-prover`
green with the two existing skips still in place; every pin in the P0-4
inventory regenerated once; the PR description lists old and new identity
values. Status after merge: **implemented, not gated**.

### Phase 2: gates

W-7. Create the tests named in contract section 9 and the
`test-riscv-recursion-soundness` step. Order by what unblocks regeneration:

1. G-9 wire map (static; catches any remaining trusted-but-unabsorbed field
   before artifacts exist).
2. G-1 and G-10 transcript equivalence and intra-lane symmetry.
3. G-2 constraint equivalence including the V-15 public boundary.
4. G-3 in-circuit negative controls (a) to (d) and G-8(a) using the P0-2 hook.
5. G-4 key freshness, G-7 shard geometry, G-8(b) and G-8(c) parent and leaf
   reconstruction.

Exit: the step exists and is green on a locally produced leaf and parent
proof. Status: **gated locally**.

### Phase 3: regeneration, once

W-6 in its stated order: rebuild the four detached binaries and the
leaf-key-setup step; leaf keys; `riscv_segment_v2_tree_key_setup.py`; parent
and root proofs through `riscv_recursive_product.py --backend cpu` and
`--backend metal`; hostile substitution controls with a regenerated
other-admission control; re-pin the K-7 inventory. Retain records in the
style of `vectors/reports/recursive-product-20260918/*/README.md` with source
revision, admission SHA-256s, binary SHA-256s and pin values. Regenerate the
`recursion-shape-audit-v2.json` through `shape_coverage.py`.

Exit: G-5 records retained for 1/2/4/8 segments; CPU and Metal artifacts
byte-identical. Status: **gated, pending suite**.

### Phase 4: qualification

Remove the `STWO_RECURSION_RUN_UNQUALIFIED_LANE` skips, restore the leaf test
body removed in `f8b64e96b`, run G-6, apply contract section 11 and flip the
ledger. The PR carries links to every gate record. Status: **qualified** at the
named revision only.

## 5. Workstreams and file ownership

| Workstream | Owns | Must not touch |
| --- | --- | --- |
| transcript | `recursion/native_scheduled_channel.zig`, `recursion/air/verifier_schedule.zig`, `transcript_shape.zig`, `transcript_program*.zig`, `fixed_wire_*.zig`, the transcript AIR and witness mirrors, `proof_transcript.zig` bypass removal | composition graph builders, provider shells |
| composition | `vm_air_composition_circuit_graph_build.zig`, `ethereum_vm_composition_graph_base_v2.zig`, `composition_circuit_reference.zig`, `vm_air_profile*.zig`, `InputProfile` root inputs | transcript files, keys |
| leaf | `segment_profile.zig`, leaf key schema and derivation, row-five sources, `detached_segment_*` | parent files |
| parent | `detached_parent_protocol_v1.zig`, `detached_parent_preparation_v1.zig`, `detached_parent_command_v1.zig`, fixed-row recipe modules | leaf key schema (consumes it) |
| provider | `hash_component.zig` shells, `poseidon2_universal_*`, `poseidon2_layout.zig`, sealed manifests | everything else |
| gates | new test files under `src/tests/riscv` and `recursion/tests`, `build_support/products/riscv_cpu.zig` step wiring | production code (reports defects to owners) |
| integrator | pins inventory, regeneration scripts, records, ledger | — |

Parallelism: transcript, composition, provider and parent can proceed
concurrently in Phase 1 once P0-1 is signed; leaf is mostly landed. Gates can
start scaffolding (recording wrappers, harness plumbing) during Phase 1 but
pin values only after the merge.

## 6. Status vocabulary

| Word | Meaning | May be used when |
| --- | --- | --- |
| designed | the contract or this plan specifies it with acceptance criteria | after review |
| implemented | code merged, focused tests pass, identities re-pinned | after Phase 1 |
| gated locally | the named gate test exists and passes on local artifacts | after Phase 2 |
| gated | gate record retained with revision and SHA-256s | after Phase 3 |
| qualified | all ten gate records at one revision, ledger flipped | after Phase 4 |
| not qualified | anything else; always say which gates are open | always |

A PR description states the status of each gate it touches using these words.
"Nearly", "almost" and "effectively" are not status words.

## 7. Risk register

| Risk | Trigger | Response |
| --- | --- | --- |
| Root inputs push a lowered constraint past degree 3 (contract C-7) | G-2 fails degree check or the builder's degree audit | Add a dedicated degree-3 input class as the contract's C-3 resolution specifies; do not reuse the Ethereum row-10 class (declared degree 4) |
| Parent key recipe is large | key JSON grows past artifact limits (`recursion/artifact_limits.zig`) | Store the recipe as typed fields with a sealed digest; the full fixed rows are regenerated, not stored |
| Hostile re-proven control is hard to construct | P0-2 hook cannot re-prove consistently | Use the native `malicious_prover_harness` capture path: prove honestly, substitute Tree 0 and re-run only the stages after it; if the native prover cannot re-run partially, add a test-only stage entry point rather than weakening the gate |
| Another native AIR change lands mid-batch | any merge to `src/frontends/riscv/air/**` during Phase 1 to 3 | The integrator re-runs the P0-4 inventory; Phase 1 re-pins once more before Phase 2; never regenerate artifacts against a moving native identity |
| Metal parity breaks after re-pinning | G-5 Metal artifacts differ | Regenerate the Metal rosters with the existing AOT tooling before Phase 3; parity is a Phase 3 exit check, not a Phase 4 surprise |
| Full-suite runtime | `test-riscv` 11 minutes, `test-riscv-prover` longer | Focused steps during development; full suites only by the integrator at phase exits |

## 8. What PR #303 does and does not close

Closed or advanced: leaf Tree 0 reconstruction from key (G-8(c), leaf half);
swapped child pin rejected before proof loading (part of G-8(b)); selected V2
physical claims bound in transcript and composition (part of W-1); scheduled
leaf Tree 0 pinned (W-9 leaf half); fixed-row families regenerated from key
geometry (prerequisite for P0-1).

Open: the parent key recipe (P0-1, G-8(c) parent half); the hostile
re-proven control (P0-2, G-8(a)); W-2 root inputs; W-3 geometry; W-4 provider
pin; W-1 for every profile and the bypass removal; all of Phase 2 to 4.

The engineer's assessment in the PR is accurate and is the model for how
status is reported from here on.

## 9. Phase 0 design records

### P0-1: parent key v3 and proof-free fixed-tree compiler

**Reviewed source boundary.** The current parent key has a manifest,
parameters, child-key SHA-256s, and a claimed fixed root. The parent
preparation path builds transcript, PCS, boundary, composition and arithmetic
rows through `detached_parent_preparation_v1.prepareFor` using verified child
captures. `PreparedV1.fillPreprocessedInto` then copies the preprocessing
part of those logical rows. The SHA-256s authenticate child keys but cannot
recover that row topology. `admit-key` currently re-runs preparation with
child proofs; that is not K-8 reconstruction.

The replacement key format is **version 3**, with a new identity domain for
both q193 and development profiles. Keep `profile`, `publication_mode`,
`pcs_config`, `manifest`, `parameters`, `preprocessed_root`, and
`child_key_sha256`. Add the following typed fields:

```zig
const ChildFamily = enum(u8) { segment = 1, parent = 2 };
const SegmentBoundaryShape = struct {
    sections: [2]SectionProfileV1, // each contains four retained counts
    memory: [2]MemoryProfileV1,   // canonical sorted entry/exit u32 addresses
};
const BoundaryShape = union(ChildFamily) {
    segment: SegmentBoundaryShape,
    parent: void,
};
const ChildFixedShape = struct {
    key_identity: [32]u8,
    preprocessed_root: [8]u32,
    manifest_seal: [32]u8,
    composition_layout_manifest_id: [32]u8,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    pcs_graph_identity_digest: [32]u8,
    sampled_value_count: u32,
    trace_tree_heights: [4]u32, // child verifier profile's commitment trees
    fri_layer_count: u32,
    last_layer_coefficient_count: u32,
};
const FixedRecipeV1 = struct {
    version: u32 = 1,
    boundary: BoundaryShape,
    children: [2]ChildFixedShape,
};
// KeyV1 gains: fixed_recipe: FixedRecipeV1
```

The stored child shapes are **cross-checks, not authorities**. Re-derive each
field from the independently pinned child key, its typed manifest and PCS
configuration. `detached_prefix_preparation_v1.PlanChannel.mixU32s` maps only
the four-word public-frame **header** to fixed `.public_frame` rows. It maps
the segment wire ID to dynamic `.wire_id`, the statement body to dynamic
`.wire`, and parent continuation words to dynamic `.span_u32`. The header's
domain, versions and word count come from `PublicDataV2.mixInto` and the
child key's source manifest. Independently pinned child expected inputs are
still required to verify child proofs, but their values are not part of
Tree0 or the parent key identity. For a parent child, use its v3 key and
recipe; a child key
must pass its own proof-free fixed-root admission in the same process,
recursively through its descendants, or be loaded from an authenticated
registry whose entries record that admission. A prior process's unqualified
assertion is insufficient. Derive the transcript operation schedule and
PCS/FRI masks by the canonical generators, not by hashing captured
operations. Derive tree column counts, offsets, composition split, quotient
bound, FRI blowup, layer count, sampled-value count and trace heights from
the child manifest and PCS geometry; the last-layer coefficient count is
`1 << pcs_config.fri_config.log_last_layer_degree_bound` in the present
producer. The claimed-sum frame has the family's **fixed component width**,
not `manifest.roster_count`: a real four-segment q193 tree reached a parent
child with 31 active roster entries and 36 claimed-sum slots. A key-only PCS
plan using the roster count was rejected at `parent-2-0-setup` by the capture
parity check; the plan generator now derives the fixed width from the typed
family, and a sparse-parent unit test pins that distinction. The stored
numeric fields are equality checks only. The existing
`CaptureLayoutV3.initForManifest` reads captured sampled-point/log arrays,
so the proof-free compiler needs a sibling layout constructor and cannot
reuse it unchanged. For a segment child, verify the retained counts and
entry/exit memory addresses in `boundary` exactly against its key's
`retained_section_counts` and `native_sum_topology.addresses`. Also pin the
child completion status if it affects any fixed graph branch. For a parent
child, the boundary shape is empty and its public word count is the fixed
continuation count. The recipe must not contain committed fixed columns,
sampled values, proof bytes, evaluated graph values, or provider outputs.
`manifest_seal` means the full pinned child-manifest seal. The separate
`composition_layout_manifest_id` is family-aware: for a segment it equals
`programGeometryShaId(manifest)`, while for a parent it equals the parent
manifest seal, matching `CaptureLayoutV3.initSegment` and `initParent`.

`rebuildFixedFromKey(allocator, parent_key, children: [2]PinnedChildKey)`
is the only fixed-tree admission path. It first checks both child-key byte
hashes, profiles, identities, child Tree0 roots, boundary shape and derived
`ChildFixedShape`s, **before opening either child proof**. Each
`PinnedChildKey` contains an independently pinned key and no expected input
or proof bytes. The function then constructs
the parent transcript, public relay, control, PCS/FRI, trace-Merkle,
boundary and arithmetic *fixed* row families from the two authenticated
child key profiles and the boundary shape; main values remain absent. It
checks the generated manifest, parameters and every fixed-row geometry
against the parent key, commits Tree0 using the production PCS, and returns
the computed root. Admission compares that output with
`key.preprocessed_root`. Key setup must run the same proof-free compiler and
compare every row digest with the existing prepared-child construction before
serializing the key. The child captures remain inputs to **witness/proof
generation only**; they cannot select fixed columns.

The detached parent command boundary must change with the schema. Its
current `verifyDirectory` takes a parent bundle, parent-key SHA-256 and
expected words but no independently pinned child keys. Require the two child
key paths and SHA-256 pins for proof-free fixed-tree admission. Child expected
inputs and SHA-256 pins remain required for subsequent child verification
(and, for parent children, recursively their
descendant admission chain or authenticated registry entry) in the command
request. `OwnedKeyV1.admit` must invoke proof-free reconstruction before
`verifyDirectoryInner` reads `claims.json` or `proof.bin`. The parent bundle's
own copies of child keys are never authorities. This is necessary for the
G-8(b) pre-proof failure claim to be true at the actual standalone boundary.

This requires a new proof-free symbolic fixed-row compiler. Calling the
current `prepareFor` is insufficient: its prefix, transcript, PCS, boundary,
composition and statement constructors consume child captures, and its
`fillPreprocessedInto` copies every logical fixed projection plus provider
and range rows. The compiler must reproduce those rows from the key recipe
and child keys alone, and be
checked family by family against the current producer
before the producer is switched over. The schedule digests above use the
existing Poseidon2 `[8]u32` authority representation; the PCS graph identity
is the existing SHA-256 `[32]u8` graph digest, independently regenerated by
the proof-free compiler. No undefined generic `pcs_profile_digest` is used.

Named failures: `DetachedParentChildKeyPinMismatch`,
`DetachedParentChildRootMismatch`, `DetachedParentFixedRecipeMismatch`,
`DetachedParentBoundaryShapeMismatch`, `DetachedParentManifestMismatch`,
`DetachedParentParameterMismatch`, and
`DetachedParentPreprocessedCommitmentMismatch`. A malformed recipe fails
before proof decoding. A changed child identity or root cannot be repaired
by re-pinning only the parent JSON.

Parent identity preimage order is fixed as follows, all integers little-endian
`u32` except `u16` profile versions, which are encoded as little-endian `u16`;
variable arrays are length-prefixed: (1) new profile-specific domain;
(2) key version, profile, publication mode, child family, PCS configuration,
and fixed-recipe version; (3) manifest format, seal, universal registry
digest, and protocol words; (4) each child's SHA-256, key identity, Tree0
root, full manifest seal, composition-layout manifest identity, both schedule
digests, PCS graph identity and numeric PCS shape, in lane order; (5)
boundary variant tag, then both section and
memory profile versions, section counts and sorted address arrays for the
segment variant; (6) `poseidon_active_rows`, followed by each
parameter row index, length and field words in catalog order; (7) parent
`preprocessed_root`. The root is hashed to bind the key identity but is an
**output** of reconstruction, never an input to fixed-row generation. Old
version-2 keys fail closed; no migration accepts them. This identity preimage
is a deterministic binary encoding, independent of JSON object field order.
Key JSON remains a transport format; a canonical JSON writer is not assumed.

G-8(b) is a pre-proof negative over the two child hashes and roots, including
newly re-pinned hostile parent JSON. G-8(c) runs this function in a separate
process with the parent key and independently pinned child keys, no child or
parent proof files, and checks every committed 1/2/4/8 parent key. The
version-3 key must stay below `detached_parent_command_v1.MAX_KEY_BYTES`
(64 MiB); an unexpectedly large recipe is a design failure, not a reason to
store raw fixed columns.

P0-1 remains under independent review until a fixed-row compiler input census
shows that this typed recipe covers every row family.

The current parent assembler's complete fixed-row census is the 29 logical
AIRs in `air/detached_parent_catalog_v1.zig`, plus the provider and range
placements populated by `detached_parent_prepared_v1.fillPreprocessedInto`.
The proof-free compiler must construct and compare the *full preprocessed
projection* of every family, including padding and committed-row mappings:

| Rows | Current producer | Key-only compiler input and obligation |
| --- | --- | --- |
| 0-10, transcript/control/payload/nonce | `detached_prefix_preparation_v1`, `detached_pcs_rows_v1`, `detached_parent_base_rows_v1` | Child key identity and Tree0, family, child statement length, typed schedule and transcript constants. Reconstruct ordered operations and frame/call counts from key-owned geometry; dynamic expected words, commitments 1/2, claims, challenges, nonce and hash outputs cannot select fixed fields. |
| 11-14, graph and statement inputs | `detached_composition_preparation_v1`, `detached_boundary_preparation_v1`, `detached_parent_statement_preparation_v1`, `detached_parent_arithmetic_v1` | Both child manifest/PCS layouts, profile versions, admitted section counts and address topology, publication mode, and fixed continuation word count. Record the symbolic composition and statement graphs with dummy witness inputs; compare graph identity and every fixed projection against the captured producer. |
| 20-29 and 33, PCS/FRI/query/Merkle | `detached_pcs_preparation_v1`, `detached_parent_base_rows_v1` | Derive tree columns/offsets, composition split, quotient bound, sample mask, fold schedule, layer count, last-layer bound, query count and path capacities from each child key's manifest and PCS configuration. Query draws, leaves, branches and sampled values remain dynamic. A proof-specific query de-duplication pattern may not select the fixed schedule; if it does, either precommit a canonical shape in the key and verify it or reject that shape. |
| 30-32, arithmetic helpers | `detached_parent_arithmetic_v1` | Rebuild from the symbolic graphs above, not their evaluated values. Require the same graph node order and fixed row geometry. |
| Provider placement 34; range placement 35 | `detached_parent_prepared_v1.fillPreprocessedInto` | Provider active-row mask comes from the derived symbolic Poseidon call count and must equal `parameters.poseidon_active_rows`; range columns are protocol constants. Compare all active and padding cells. |

The current `prepareFor` merges the base and arithmetic rows and derives its
manifest/parameters from their concrete logical rows. The new compiler must
derive those same values from the key-only symbolic rows, validate them
against the parent key, and only then commit Tree0. Per-family parity tests
must use at least two distinct valid child proof pairs of the same admitted
geometry; equal roots for one captured fixture alone do not establish that
dynamic child values never select a fixed cell. A source-level review has
identified no decisive value-dependent statement branch, but that is not
yet a parity result.

**Non-identity prototype checkpoint (2026-10-19).** The composition sample
layout, PCS/FRI schedule and PCS transcript suffix shape can now be derived
from child key geometry without a proof. The captured production path checks
tree heights, lifting, PoW parameters, query count, sampled-value count,
fixed claim width, FRI layer count and terminal coefficient count against
those key-derived shapes before constructing parent rows. Fresh
two-segment q193 setup rederived byte-identical parent key JSON (SHA-256
`e5d26214f9982870cee8f4180d4a1cf01c1526dd2e81252cc0ceb872ad4e1dfa`)
and a separately verified root. A four-segment diagnostic then proved and
verified both first-level parents and a parent-child root after two exact
parity fixes: the parent claimed-sum frame has 36 slots despite 31 active
roster entries, and compact Poseidon2 already contains the full-IO direct
constraint, so composition must not append the wide AIR's extra shell root.
The final root proof SHA-256 was
`f78e1c17b1adbe27a00ab73085c0aff0a3548d8a00c42b777cce9a8f491c4ea6`;
its standalone parent gate accepted 28 cases. After extracting the key-only
shape into `detached_pcs_key_shape_v1.zig`, the same four-segment root key
remained byte-identical and the proof retained that exact SHA-256; a separate
segment-child parent proof also passed 28 gate cases with the new producer.
These runs used an uncommitted
source tree and are **diagnostic only**: they do not establish proof-free
parent Tree0 regeneration, P0-1 review, or any G-1 through G-10 publication
record.

**Parent fixed-row census (2026-10-19).** A diagnostic producer hook now
hashes every committed parent Tree0 placement after `fillPreprocessedInto` and
before commitment (`STWO_RISCV_PARENT_FIXED_CENSUS=1`). Re-deriving the two
first-level parents from the four-segment q193 fixture produced byte-identical
keys to the earlier setup and emitted 31 active row digests each. Their parent
manifest seals and every placement's log size and column count match. Fixed
projections differ in rows 0, 2-5, 11-14, 23, and 30-32; rows 1, 6-10,
20-22, 24-29, and 33-35 match. The provider active-call counts also differ
(180691 versus 180714), although provider Tree0 row 34 and range row 35
match. This confirms the key-only recipe must carry or independently derive
the varying row inputs and must reproduce *all* row digests, including rows
with no preprocessed columns. The two child pairs have different admitted
boundary profiles and expected statements, so this comparison does **not**
isolate proof-value dependence. A second four-segment workload changed the
initial memory word from 14 to 15 while retaining the same first-pair
boundary profile. Its four native and leaf proofs and first parent key setup
completed. The first parent had the same manifest seal, all 31 placement
geometries, provider active-call count, fixed root and **all 31 fixed-row
digests** as the original workload, although both child key files and
expected public inputs changed. The parent key SHA-256 changed from
`15ff4f2aa925df9474c467501b1745e363e98fbf4472c40ddbd8986510a67ce6`
to `7d1e6e8266a004f16c6709687dd90ec8e5d469910d31a33ac2ccb7180ba48cd4`
solely because it pins the changed child key bytes. This is direct evidence
that those changed public words did not select fixed cells in this admitted
shape; it is not a universal proof of independence across all profiles. The
source-level mapping confirms the result: only the public-frame header is
fixed, while expected statement words enter dynamic `.wire` or `.span_u32`
rows. Diagnostic logs and derived keys are under
`/tmp/stwo-riscv-layout-4-20261019/tree/*-census*` and
`/tmp/stwo-riscv-census-alt-20261019/`; they are not publication records and
must be regenerated into retained evidence after the identity batch.

Rows 34 and 35 now share a manifest-only generator between the current
producer and the future proof-free compiler
(`detached_parent_fixed_tables_v1.zig`). Re-deriving the first parent after
this extraction produced the **same serialized key SHA-256**
`15ff4f2aa925df9474c467501b1745e363e98fbf4472c40ddbd8986510a67ce6`
and all 31 identical committed-row digests. The focused recursion soundness
step and parent producer build passed ReleaseSafe. This extraction closes only
those two fixed table families, not parent Tree0 regeneration.

The PCS sample-layout subproblem exposed why sample counts alone cannot define
a parent graph. The admitted universal typed interaction rows emit
`[previous, current]` on their final secure columns; the shared Poseidon2 and
range-table providers emit `[current, previous]`. Both have two samples, but
the PCS assigns DEEP powers in their actual order. `CaptureLayoutV3` now
derives the ordered layout from the admitted manifest, and detached child PCS
preparation rejects a capture with a different order before constructing the
parent rows. This is one key-only compiler input, not a proof-free Tree0
reconstruction or a qualification gate record.

The key-only FRI/PCS template also reconstructs circuit profiles, graph
identities, column logs, and all ten preprocessing row arrays for families
20–29. Focused ReleaseSafe gates compare those arrays against genuine verified
SegmentV2 and recursive-parent captures at q193. A separate fixed-column
projector writes selected left/right lanes in parent row order, including the
production committed-row permutation and zero padding; its real-proof parity
tests compare every committed cell against the producer's logical-row
projection. A separate ReleaseSafe gate verifies two independently pinned,
distinct first-level parent proofs and then projects their two lanes together.
The fixtures remain diagnostic `/tmp` inputs, so these are
development checks, not retained G-8 evidence. The other parent Tree0
families, parent-key v3 identity, and independent whole-Tree0 root remain.

The prefix through Tree2 now also has a key-only operation constructor for
both SegmentV2 and recursive-parent child families. Genuine q193 proofs
confirm exact operation order, fixed payload values, and transcript frame
lengths. The fixed frame/call/word/payload counts are derived from those
operations and compared with the captured producer. Prefix and PCS-suffix
control rows each use one generator in the producer and key-only path. The
PCS/FRI checker control rows derive from the child's key-only verifier plan.
Together they reconstruct every row-0 control entry for either child lane,
and genuine segment and recursive-parent captures pass byte-for-byte row
parity. The other parent Tree0 families and independent whole-Tree0 root
remain.

The key-only transcript-frame topology now also reconstructs preprocessing
for parent rows 2–5 and 8–10 from each admitted child key. It uses the same
fixed-row builders as the producer, with zero-valued synthetic calls only to
derive topology and fixed metadata; it does not treat those calls as witness
values. Genuine q193 segment and recursive-parent proof checks pass in
ReleaseSafe, including the live-channel rule that a PoW draw uses a copy and
does not advance the transcript draw ordinal. These checks are diagnostic
parity for those row families. Rows 11–14 and 30–32, parent key v3 identity,
and a proof-free whole-Tree0 commitment still block G-8(c).

The symbolic composition graph now builds from an admitted segment or parent
key without a proof capture. ReleaseSafe parity checks compare its layout
identity, graph identity and every input binding against a genuine q193
segment proof and two distinct verified parent proofs. The parent-child
boundary graph also has a proof-free key path: it uses the fixed continuation
word count and dummy input values to build the graph without evaluating a
witness. An opaque graph-only owner prevents that synthetic state from being
used as an admitted boundary witness. Its graph identity, bindings and all
published/raw word-node projections match both genuine parent proofs. These
are inputs to the remaining fixed-row compiler, not yet rows 11–14 parity or
G-8(c) evidence; the segment-child boundary and segment-segment statement
graphs still require proof-free builders.

The parent-parent statement fold now also has a graph-only constructor from
two child keys and the publication mode. It builds the canonical statement
and adjacency constraints using the key-only boundary graphs, while omitting
value-dependent `continuation.fold` and circuit evaluation. A four-leaf q193
tree supplies two distinct verified first-level parent proofs; their captured
root-fold graph identity, input bindings, and child-boundary identities match
the key-only graph in ReleaseSafe. This is diagnostic parity for the
parent-parent topology. It does not yet bind a v3 parent key or prove the
segment-segment statement graph can be rebuilt without statements.

For segment children, `detached_boundary_key_shape_v1.zig` now derives the
canonical wire length, four retained-section placements, the pinned entry
and exit address slices, and the exact Poseidon request count from the child
key alone. It runs the same sparse-memory traversal with zero byte values to
count requests; zero bytes do not remove leaves. A genuine q193 segment proof
confirms that the key-derived wire length and request count equal the captured
boundary graph's provider calls and bindings in ReleaseSafe. The next step is
to record the segment boundary graph using this shape and synthetic values,
without the concrete-statement validation or native hashes that belong only
to the evaluated witness path. This is now implemented as
`detached_boundary_preparation_v1.SegmentKeyGraphV1`; its shared builder
matches a genuine q193 segment's graph identity, input bindings, provider
bindings and raw wire projections in ReleaseSafe. It is graph-only and does
not admit a witness. The remaining parent Tree 0 work is to compose all
key-only graphs and fixed row families into the complete commitment and
verify its root against an independently produced parent key.

`detached_parent_statement_preparation_v1.SegmentKeyGraphV1` now records the
segment-pair fold graph from two keys and the admitted intermediate/root
publication mode. It does not call the value-dependent statement hint
preparer or evaluate the circuit. Two distinct adjacent q193 child pairs
(leaves 0/1 and 2/3 of the four-leaf roster) matched genuine captured graph
identity, every input binding and both boundary graph identities in the
ReleaseSafe `test-recursive-segment-v2-segment-pair` step. The first diagnostic
attempt deliberately used `.root` for a nonterminal pair and failed
`RootHeightNotMinimal`; the fixture's pinned parent key requires
`.intermediate`. This is parity evidence for the key-only graph, not a
qualified parent Tree 0 or a substitute for G-8.

The parent arithmetic graph-lane/export construction is now shared by its
evaluated producer and `fixedFromChildKeys`. The latter accepts only two
child keys plus publication mode, rebuilds composition, boundary, PCS/FRI
and fold graphs, then uses the canonical arithmetic-fusion fixed-row walker.
ReleaseSafe parity compares every committed fixed column (including padding)
for arithmetic rows 14 and 30-32 against captured production rows. The
shared graph-input/bridge emitter also reproduces every fixed field of rows
11 and 12, and the same authenticated plan reproduces every fixed field of
row 13. This passed for both distinct segment pairs and for the verified
pair of first-level parent proofs. The parent proof producer still compiles
after the shared-reference refactor. The key-only builder supplies the
protocol-fixed selector value to the shared row emitter; all other synthetic
values are graph placeholders, and no proof data is accepted by this API.
The proof-free `detached_parent_fixed_tree0_rebuild_v1` now composes the
key-derived base, graph, arithmetic and PCS/FRI rows with the manifest-owned
provider/range tables. It reproduces **every Tree 0 column and padded cell**
from the current production preparation for two distinct segment pairs and
one pair of first-level parent proofs in ReleaseSafe. Rows 1, 6, 7 and 33
have no Tree 0 columns. The compact inverse and linear rows also contain
proof-kind parameters after their preprocessed fields; only the latter are
projected into Tree 0. The integration check now independently commits both
sets of columns through the production PCS and compares the Poseidon2 roots.

`detached_parent_key_manifest_v1` also derives the complete manifest seal
and exact `poseidon_active_rows` from child keys. It counts only selected
trace/FRI paths, subtracting each packed-leaf subtree from the FRI sibling
depth. The segment pairs require respectively 180,691 and 180,714 provider
calls; the first-level parent pair requires 176,468. All three derived counts,
manifests and committed roots match the genuine producer in ReleaseSafe.
All parameter families are checked against key-only base/graph rows or the
canonical PCS profile, proof-kind selectors and shared parameter tags.
Two negative parent-pair controls change the active provider count and a
control parameter while keeping the rest of the producer fixture intact;
both fail with `DetachedParentParameterMismatch` before Tree 0 commitment.
This was stronger G-8 construction evidence, but **not G-8 qualification**.

**Local v3 integration checkpoint (uncommitted).** The parent key now carries
the typed fixed recipe and a version-3 identity. The producer deep-copies the
recipe while genuine child owners are alive. The standalone parent verifier
requires an external, bounded postorder key registry. It checks every edge's
child-key SHA-256, recursively rebuilds each leaf's native and outer Tree 0,
derives each parent manifest and parameters from child keys, commits each
parent Tree 0 through the production PCS, and compares the pinned root before
opening the candidate's claims or proof. The setup script emits relocatable
registry paths and runs a proof-free fresh-process admission for each parent.
The old version-2 parent key fails with `DetachedParentProfileMismatch`.

Local q193 evidence: a new two-segment v3 parent key, proof and independent
expected words verified; a four-leaf tree with two v3 intermediate parents
and one v3 root verified in a fresh process after recursive key-only
admission. Re-pinned hostile parent keys with a changed root, child pin or
recipe failed with `DetachedParentPreprocessedCommitmentMismatch`,
`DetachedParentChildKeyPinMismatch` and `DetachedParentFixedRecipeMismatch`,
respectively. The proof-free four-leaf admission took 23.3 s on this host.
These fixtures are local diagnostics until committed gate records pin the
source revision, input SHA-256s and binary SHA-256s. G-8(a)'s consistently
re-proven hostile Tree 0 control, the 8-leaf path, CPU/Metal parity and the
other gates remain open.

The v3 two-segment parent gate completed 27 fresh-process cases using a
relative-path key registry. Every altered claim, changed key/profile,
incorrect independent pin, and changed canonical/session/lineage word
rejected at a named boundary; the retained input files were unchanged. This
is a local script check, not a final-revision publication record. The gate
script now relocates every child key path when it copies the registry for a
hostile re-pin, and uses the canonical 436-word continuation ABI for v3.

**Local G-8(a) native-control checkpoint (uncommitted).** SegmentV2 now
threads a preprocessed-cell mutation only through test builds. It changes an
unused bitwise-table tuple, so ordinary `Engine.prove` completes with AIR
constraints satisfied and redoes the commitment, transcript, openings and
PoW. The focused `test-segment-v2-native-proof` and
`test-segment-v2-hostile-tree0-q193` ReleaseSafe tests passed: the hostile
Tree 0 root differed from the honest root, the public statement was identical,
and native verification rejected the proof with
`InvalidPreprocessedCommitment`. A test-only verifier that omits only this
independent-root comparison then accepted the canonical serialization of the
same hostile proof through all remaining native AIR/PCS/FRI checks and
produced a validated capture. Outer preparation's production root guard
rejected that capture against a root freshly rebuilt from admitted geometry
with `InvalidNativePreprocessedCommitment`. This stops before an outer proof
exists: there is no standalone outer proof byte stream to claim was rejected.
The test still needs a retained hash-pinned record, and G-8(a) remains open
under the contract's strict standalone-verifier wording.

**Local G-9 payload-custody checkpoint (uncommitted).** The existing
`fixed_wire_custody_test.zig` inventories all ten fixed-wire fields and
counts the verifier-plan routes, including physical claims and both PoW
checks. A new focused V2 test walks every emitted transcript payload row
against its executed mix frame. It checks the exact frame and word offsets,
typed source coordinates, constant mask and pinned value, and input-use
multiplicity. The two nonce payloads have zero input-relation uses and each
has a dedicated PoW frame; ordinary dynamic words have at least one use.
`zig build test-riscv-recursion-soundness -Doptimize=ReleaseSafe -j2` passes.
This exercises the small V2 fixture, not the full admitted profile or all
Merkle/FRI authentication paths. G-9 remains open until the whole-wire
static map and final-revision retained record pass.

The static full-profile custody test now enumerates every limb coordinate of
the four native commitments, 28 aggregate claims, 51 physical claims, 1,081
sampled values, five FRI commitments and the last-layer coefficient. It also
requires exactly one plan absorption per FRI commitment, in addition to the
existing Merkle-path, fold and queried-value counts. The focused ReleaseSafe
suite passes. This closes the scalar-coordinate inventory locally, but does
not yet prove the Merkle/FRI path authentication map or production-key pinning
of every constant payload; G-9 remains open.

The first focused-suite pass neither imported nor selected the V2 payload
test; that coverage claim was too broad. The focused root and its pinned name
filters now include it and the outer-admission control. The ReleaseSafe step
passes with both selected (35 named tests in the first corrected run). The
latter includes
new negative controls for an active queried value, active trace sibling, FRI
opening value and active FRI sibling: each mutation is rejected against the
already admitted proof identity. This establishes wire/capture custody at
admission, not in-AIR authentication of those paths; G-9 remains open until
that separate route is checked.

A focused static AIR-custody check now builds and authenticates the typed
Merkle-root, Merkle-path, trace-leaf, FRI-anchor, FRI-node, FRI-leaf and
FRI-verifier-input definitions together. It pins the emit/consume edges on
`recursion_merkle_node`, `recursion_fri_merkle_local_root` and
`recursion_fri_merkle_value_word`. The focused step also selects the existing
Merkle-path mutation, FRI-anchor and FRI-input tests; ReleaseSafe passes.
This shows the intended in-AIR relation chain exists at the component level.
It does not establish whole-proof lookup cancellation or a standalone outer
verifier rejection for each hostile path, so G-9 is still open.

**Local G-1 admission hardening checkpoint (uncommitted).**
`transcript_program_v2_program.Program.validateAgainst` now reconstructs the
entire verifier-owned instruction expansion from the admitted plan, PCS
configuration and statement geometry before accepting a program. Previously
it checked a self-hash and shallow instruction counts, which let a re-sealed
instruction array with a duplicated Tree-2 mix and missing Tree-1 mix pass
that validation. The new negative test re-seals exactly that altered array
and requires `AuthorityMismatch`. The focused ReleaseSafe recursion step
passes. On this dirty worktree at HEAD `cb9c11309955ad66eef7d053d4b22fa758c2cbd9`,
the q193 one-segment key-setup runner built and generated a genuine native
proof while `STWO_RISCV_TRANSCRIPT_EQUIVALENCE=1` compared producer, fresh
native verifier and scheduled recursive frames. It returned exit 0 with
193 queries, 16 PCS PoW bits, 1,330,017 proof bytes and no outer proof.
The runner binary SHA-256 was
`c26fa7fa2a84037e626550be30ba09ff0e0ea4683a0c590921bb0296460adf09`.
The temporary setup and key SHA-256s were
`0ef35ff205a7d27be049fdd31dcb601c9c47e3f1bf7fded7e3ea1e3c499074f5`
and `45d2465a37cdc24d3a84fcc494411215b3042c1ba025cd52090c48ded0a7d71d`.
This is a diagnostic against uncommitted source, not a retained G-1/G-10
record at one final revision; both gates remain open.

**G-7 fresh-process gate extension (uncommitted).** The existing Zig command
tests already exercise `n_rows`, `log_size`, and `n_columns` against both the
original key pin and a newly pinned but geometrically false catalog. A
duplicate fixture-only test was removed. The detached leaf replay script now
replays a genuine proof against each newly pinned catalog mutation, plus a
newly pinned wrong native Tree 0 root, keeping the expected public statement,
claims and proof bytes unchanged. It demands a named native geometry or root
error and repeats each case with `proof.bin` absent to prove that rejection
precedes proof I/O. This exercise exposed an ordering gap for `n_columns`:
the command read `proof.bin` before `verifyWithChannel` checked descriptor
geometry. The command now calls the same `KeyV1.validateExpected` boundary
as the verifier immediately after decoding independently supplied expected
words, before claims and proof I/O.

On the dirty current tree at HEAD `cb9c11309955ad66eef7d053d4b22fa758c2cbd9`,
a freshly exported one-segment, one-address, seed-13 q193 workload generated
its own independent key and a 2,496,153-byte wrapper proof. The standalone
single-root verifier accepted it. The enhanced gate then passed 21 fresh-
process cases in 6.07 s. All four newly pinned hostile keys rejected with
the proof present and absent: changed root, row count and log size returned
`InvalidNativePreprocessedCommitment`; changed column count returned
`InvalidNativeDescriptorGeometry`. The ReleaseSafe catalog-admission and
focused recursion-soundness test steps passed. The local diagnostic report is
`/tmp/stwo-riscv-g7-current-20261019-2/gate-report.json` (verifier SHA-256
`7c09f5fb63f939e40ceee92228c233e3085ef7770cbc834a3b2efa89841c3566`, key SHA-256
`a4d5a64ed87f6946eb32bc725abb2f7e658ce03620793485508c1db65456a3fc`). G-7 is gated
locally; its final-revision retained record is still required. G-8(a)'s
consistently re-proven hostile Tree 0 remains open.

**Local G-10 one-leaf checkpoint (uncommitted).** The leaf replay gate now has
an explicit `--require-transcript-equivalence` mode. It authenticates the
producer receipt against the candidate's key, claim, proof and expected-wire
hashes, requires a producer recording, runs the standalone verifier with its
recording channel, and compares the two full-recording SHA-256 identities.
The producer already compares its recording with an in-process verifier frame
by frame before publishing the candidate. A new q193 one-segment CPU
production under this mode emitted recording identity
`476eeda7aa878a0da315113b8c39bd1a2fcfeae0b59d8f3c5e83f4b3b5fc2a93`; the fresh
standalone verifier produced the same identity and all 21 replay cases passed.
The local report is
`/tmp/stwo-riscv-g7-current-20261019-2/recording-gate-report-v2.json`.
The same current-source workflow then exported and proved two contiguous
q193 segments, each with an independently derived key and its own outer proof.
The pair gate passed 26 fresh-process cases, including complete adjacency,
wrong ordering, duplicated children, and producer/fresh-verifier recording
identity equality for both children. Its local report is
`/tmp/stwo-riscv-g10-pair-20261019-1/gate-report.json`. This pair-only gate
establishes one- and two-leaf recording symmetry locally; the parent proof is
covered in the next checkpoint. G-10's full 1/2/4/8 matrix and final-revision
record remain open.

**Local two-segment root checkpoint (uncommitted).** A current-source CPU
key-setup run derived the q193 parent key from independently pinned two-child
inputs and passed proof-free parent-key admission. With
`STWO_RISCV_OUTER_TRANSCRIPT_EQUIVALENCE=1`, the full tree gate then proved
both leaves and a `tiny-memory-root-v2` recursive parent, independently
verified every proof, and accepted a single root. The tree report at
`/tmp/stwo-riscv-g10-pair-20261019-1/full-tree/report.json` says `passed=true`;
its two leaf replay gates passed, and the parent gate passed 27 hostile cases.
Producer/fresh-verifier recording identities matched for leaf 0, leaf 1 and
the parent. Parent candidate production took 10.08 s; the 262.07 s complete
gate includes serial hostile replays and is not a proving-time benchmark.
This verifies a genuine two-segment recursive root locally. The final-revision
1/2/4/8 CPU/Metal matrix, G-8(a)'s hostile re-proven native Tree 0, and the
remaining composition/wire controls are still open.

### P0-2: consistently re-proven hostile Tree 0 control

The existing `test_witness_hook_core.Mutation.preprocessed` hook mutates a
preprocessed cell before its commitment in the native prover. Thread that
hook through the SegmentV2 test configuration using a
field compiled only when `builtin.is_test` is true. Keep the mutation entry
point in test support beside `src/tests/riscv/malicious_prover_harness.zig`;
production commands, service requests and environment variables must have no
way to set it. The test changes one otherwise valid fixed cell, then lets the
native prover redo the commitment, Fiat-Shamir draws, openings and PoW. It
checks that the resulting native proof is internally consistent and that its
Tree 0 root differs from the canonical key root. Replacing only a serialized
root is not this control.

The ordinary native admission path must reject this proof. For the outer
control, a test-only capture adapter may carry the consistently re-proven
proof past *native admission only*, so the recursive verifier itself reaches
the Tree 0 constraint. Its expected error is `SourceMismatch` at the
scheduled Tree 0 comparison, or the named detached preprocessed-commitment
mismatch if rejected earlier by the standalone leaf verifier. Preserve both
observations in the retained test record. If construction rejects before an
outer proof exists, there is no proof byte stream for a standalone verifier
to reject; the test must explicitly record that boundary rather than claim
a nonexistent verifier run. A validly serialized hostile outer candidate, if
one is produced, must be rejected by the standalone verifier.

**Local boundary check, 2026-10-19 (not retained G-8 evidence).** The q193
hostile native proof is generated with the test-only fixed-cell mutation before
commitment and passes the remaining native AIR/PCS/FRI checks through the
test-only capture adapter. The ordinary native verifier rejects its Tree 0.
The same captured proof now also fails
`PreparedNativeV2LeafOuter.init` with
`InvalidNativePreprocessedCommitment` when supplied the independent canonical
root; the focused `test-segment-v2-hostile-tree0-q193` run passed. This is the
earliest ordinary outer boundary, so no hostile outer proof exists for a
standalone verifier in this check. G-8(a) remains open until its stated
standalone negative control is produced and retained, or the gate is amended
through review to accept this earlier rejection boundary.

**Local standalone control, 2026-10-28 (not final-revision qualification).**
The same test-only native capture was instead prepared under its hostile root
and used to produce a complete q193 outer proof. The test verified that outer
proof under the hostile candidate's self-pinned key, deliberately omitting
canonical native-root admission only in the test. The ordinary standalone
leaf verifier then rejected the retained 2,483,181-byte candidate with
`InvalidNativePreprocessedCommitment`, both with the proof present and with
`proof.bin` absent. The native proof, canonical statement projection, claim,
outer bundle, hashes and fresh-process logs are retained at
`vectors/reports/riscv-recursion-20261028/hostile-tree0-q193/`. This closes the
G-8(a) construction gap locally. The record was generated on the uncommitted
worktree, so G-8(a) still needs final-revision regeneration and review before
the ledger can treat it as qualified.

### P0-3: transcript and composition equivalence oracles

`src/tests/riscv/recursion_transcript_equivalence_test.zig` is the G-1/G-10
oracle. For each admitted profile, create a genuine native proof and record
the native producer's ordered mix/draw/PoW frames. Drive a fresh native
verifier through `native_scheduled_channel.Channel` and record its frames;
run `transcript_program_contract.Execution.replayNative` against the exact
recorded execution. Repeat for every leaf and parent in the 1/2/4/8 corpus
using a separate-process standalone verifier. Compare frame kind, payload
length, payload bytes, draw result and PoW result in order. Assert that the
physical-claim frame count equals `physicalClaimCount`. A mismatch prints the
profile, proof identity, first differing frame index, both frame kinds and
payloads, and source revision.

`src/frontends/riscv/recursion/tests/vm_air_composition_equivalence_test.zig`
is the G-2 oracle. For each profile, derive 64 reproducible seeds as
SHA-256(`"riscv-g2/v1" || profile-id || little-endian u32(index)`), map bytes
to canonical field words by rejection sampling, and generate sampled points,
random claim vectors and challenges from the same stream. Evaluate the
recursive composition graph and native
`Components.evalCompositionPolynomialAtPoint` on identical inputs, comparing
the total and each component where the native evaluator exposes it. Check
the nine memory/root constraints against public words 222 and 232, and the
V-15 public LogUp rows against `-public_logup.sum(public_data, relations)`.
On mismatch print seed, profile, component and first differing constraint
index where instrumentation can expose one. No hard-coded expected aggregate
can substitute for this differential check.
