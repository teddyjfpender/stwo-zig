# M6 fold-v3: standalone root-only receiver, native VK table, parallel derive

Stream `fold-v3` (RV64 M6), branch `codex/rv64-m6-fold-v3`, base `95d40063d` (M5 integrate), 2026-11-05.
Plan: `rv64-gpu-10x-plan.md` §4 (receiver line), §5 M5/M6 verifier column. Predecessor: `rv64-m5-rootverify.md`.
Code: `rv64_recursion/root_verify.zig` (table, keys, k-ary root tree), `root_verify_main.zig` (CLI), new
`root_derive.zig` (parallel full-tree receiver for derive); minimal hook in `ethereum/setup_cache.zig`
(`Options.store_bulk`). Receipts: `vectors/reports/rv64-m6-20261105/fold-v3/`.

Labels: **[M]** measured (receipt exists), **[D]** derived from measured numbers, **[E]** estimate.

## 1. What changed and what is switched on

| piece | where it runs | status |
|---|---|---|
| native VK section in the receiver table (schema `rv64-vk-receiver-table/v1`, root-v2) | `derive-vk-tables` writes it; `verify-root-candidate` restores native keys + FIXED bindings from it | **on** in the receiver binary (the only root-only path) |
| parallel derive: native keys built on 16 threads, native verify overlapped, leaves on `STWO_RV64_DERIVE_LANES` (8) lanes, folds per level with one authority build per fold class | `derive-vk-tables` | **on** |
| bundle load overlapped with image/program rebuild; process exits after the accepted statement is written | `verify-root-candidate` | **on** |
| plan-driven (k-ary-aware) expected root: `ready_dag.Plan.initArity`, `foldClassKeyK`/`foldDigestK` hash `Bridge.versionWord(k)` | `verify-root-candidate` | **on** (identical to the binary carry for k = 2: unit test over 1..17 leaves) |
| fold v3 in circuit (T_rec membership, NS interval chain, PCD self-VK) | — | **not started in circuit** (§5) |

Proof bytes are untouched: every change is receiver-side. Proofs measured are the M5 default-format proofs (r1 exact
binary, flat native; byte-identical to the M3/M4/M5 default receipts) and the M5 canonical-profile proofs.

## 2. The native VK section and why restoring from it is sound

Before M6 the root-only receiver spent 12 of 13.7 s on 24628607 rebuilding native setup: `Keys` (CPU/truth setup with
source commitments, 7.3 s) and the candidate FIXED authority (`FixedSet`, 4.7 s) [M, M5 summary]. Root-only needs them
only for receiver-side admission (`Inventory`, `CpuLeaf.expectedWords`, `services_root.check`) and for the leaf class
key (`leafKey`: source root, fixed identity, fixed root).

**What the section holds.** One entry per native setup component, keyed by `setup_cache.componentKey` (SHA-256 of the
code identity = SHA-256 of the running executable, the suite, the component kind and parameters: geometry + bridges
for CPU, (log, policy/op/kind) for truths, and the receiver-pinned program identity). The value is the component's
VK-only setup artifact (`setup_cache.zig` header + VK: suite identity, source root and source column logs, candidate
blowup, FIXED identity, FIXED root, cell count, candidate column logs; about 0.4 KB).

**Who writes it.** Only `derive-vk-tables`: it builds every component from source in `.prover` mode with an empty
private directory (every lookup is a miss, so every source key is committed and every FIXED key sealed exactly as
the M5 receiver did, now on 16 threads), runs the full independent receiver on top of those keys (native verify +
every recursion proof), then persists the VK-only artifacts (`store_bulk = false`) and records them. Never a producer
store, never `STWO_ZIG_RV64_SETUP_CACHE` (still refused at entry), never a file the producer can name.

**How verify uses it.** `verify-root-candidate` writes the table's artifacts into a fresh private directory of its
own process and opens the setup cache in `.verifier` mode on it. For each component the builder still constructs the
component from the receiver's own image and declarations; the seal seam then replaces only the source commitment by
the artifact's root, after checking the artifact's suite identity and every source column log against the columns it
just built (`Seam.restore`). The candidate FIXED key is adopted root-only. A component whose key is not in the table
is built from source (reported as `native_table.misses`); nothing is ever taken from elsewhere.

**Trust argument.** The section is part of the table and is covered by `table_root` (root-v2 binds every entry key
and every artifact byte). The table was already the trust root of root-only mode (`rv64-m5-rootverify.md` §3.2, A2):
whoever writes it chooses the root circuit. The native section adds no new trust: it holds values the same receiver
binary computed from the same pinned source, and the operator pin `--table-root` authenticates them together with
the OM31 keys. Concretely, a forged native entry can change (a) the source root / FIXED identity / FIXED root of a
binding and (b) the native shape logs (refused by the seam unless they equal the rebuilt columns). (a) flows into the
leaf frame words, the execution identity and `leafKey`; the leaf circuit hashes the FIXED identity/root into its
statement, so a value different from the one derive used selects no table leaf (`VkTableMissingLeafClass`) or yields
a different root digest (rejection). It cannot make a wrong statement accept without also forging the pinned root.
The artifact header code identity must equal this binary's, and the header and VK section are SHA-256 sealed
(`setup_cache.Artifact.read`), so a stale or relabelled artifact is refused even before the pin.

**Merge.** `--merge` unions native sections; a repeated key must carry the byte-identical artifact
(`VkNativeClassMismatch`), the analogue of the leaf/fold class premise checks. Setup is a pure function of the key,
so this has never fired on the dev blocks.

## 3. Parallel derive (same checks, new schedule)

`root_derive.verifyTree` performs exactly the checks of `execution_wrap.verifyExisting`: receiver admission, every
leaf graph built trace-only from receiver setup and receiver frame words (`RecursiveLeafFrame`), every leaf/fold
proof freshly verified under an authority built by this process, every fold digest recomputed from its children
(`RecursiveFoldDigest`), the root re-verified, its bytes compared to `root.proof`, `services_root.check` repeated.
The tree is the receiver's own `ready_dag.Plan` (node ids = proof file ids, `publication.requireExisting` first).
Folds of one level that share a fold class reuse one receiver-built authority (the FOLD_CLASS_CACHE rule, judged
admissible in canon-vk review N3: built from an honest trace-only graph in this process, never persisted). Derive's
outputs (table) are cross-checked twice: the root-only self-check against the parallel result, and the separate
`--audit` run (the unchanged sequential receiver) on every gated block.

## 4. Measurements

See the receipts and `vectors/reports/progress/fold-v3.jsonl`. Every verify is a separate fresh process (CPU only,
no GPU, `STWO_ZIG_RV64_SETUP_CACHE` unset, private native dir), pinned with `--table-root`. The pod was shared with
other M6 streams (1-min load 10-30): single observations, above the quiet bar.

## 5. Fold v3 in circuit: status and next steps

Not started in circuit this session. The time went to the receiver pieces above, which carry the verifier column on
the current formats. What fold v3 must still do (unchanged from the binding note and P2 corpus IDs F301-F308):
- `T_rec` membership of every child VK at a fold (`vk_table.verifyMembership` with a guessed index; CV2');
- the NS interval chain with the corrected `seg_lo` range check (`node_summary.foldInterval`, CV3' A1);
- PCD self-VK: `vk_fold` as a public input passed up unchanged, child VK in {T_rec leaf} ∪ {vk_fold};
- every receiver-side §9.2 check (inventory, manifest, frames, closure) moved in-circuit, after which the root
  statement alone (table roots, `vk_fold`, chain, κ, χ) is what the receiver recomputes, and `--audit` stops being
  the acceptance path for the compat profile;
- under named profile `m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1` (reserved by profiles), never the default.
The receiver side is ready for it: the plan-driven k-ary tree and `foldClassKeyK` are in place, and the native VK
section becomes the T_nat leaf source once native-format's strict roster (`rv64-m6-native/v2`, NF2) lands.
