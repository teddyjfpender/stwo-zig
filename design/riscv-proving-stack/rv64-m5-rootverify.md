# M5 rootverify: receiver VK tables and the root-only verifier

Stream `rootverify` (RV64 M5), branch `codex/rv64-m5-rootverify`, 2026-11-04. Plan §4 (receiver line), §5 M5 "verifier"
column; binding note `rv64-m5-binding.md` §5. Code: `src/integrations/riscv_cpu/rv64_recursion/root_verify.zig` (keys,
table, tree digest, root verify), `root_verify_main.zig` (CLI), hooks in `om31_native/execution_wrap.zig` (2 lines) and
`circuit_cpu/om31/prove.zig` (`Authority.initVerifier`). Corpus: `scripts/rv64_m5_rootverify_corpus.py`.

Labels: **[M]** measured (receipt exists), **[D]** derived from measured numbers, **[E]** estimate.

## 1. What the receiver does now

Two new modes of the CPU-only receiver binary (`rv64-word16-ethereum-recursion-receiver`); every older mode is unchanged.

| mode | cost | what it verifies |
|---|---|---|
| `derive-vk-tables CONFIG OUT TABLE FIXED [RECV] [--merge T] [--source-commit C]` | one-time per geometry set | today's full receiver (native + every recursion proof, fresh authorities from source, no store, no setup cache) and records each receiver-built OM31 authority as a **compact verifier key** keyed by class; then self-checks root-only against the full result |
| `verify-root-candidate CONFIG OUT TABLE FIXED [RECV] [--audit]` | per block | receiver admission (statement, inventory, manifest, frames, RAM/KIO/Wire closure, terminal output) + leaf digests + fold digests from table VKs + **one** OM31 proof: `recursion-om31/root.proof`. `--audit` also runs the full-tree receiver and requires the same root digest and root authority |

The root-only path never verifies or reads a native proof body (beyond the bundle's file-hash load check) or a child
recursion proof. Leaves verify natives in-circuit; folds verify children in-circuit.

## 2. Compact verifier key (the OM31 VK)

`VerifierKey` = preprocessed column layout (45 × (column id, log)), component row logs, `n_outputs`, bound-AIR constraint
count and max evaluation log, FIXED root, identity. About 0.5 KB.

`Authority.initVerifier` rebuilds a verify-only authority from it:
- the bound AIR is the pinned AIR bundle (`parsePinnedAir`, sha-checked) bound to the layout's row logs, exactly as `init`;
- the FIXED column logs are the layout logs (identical to `pp.columns` order by construction of `pp.layout()`);
- the identity is **recomputed** from (root, logs, n_outputs); a key whose recorded identity, logs or bound totals differ
  is refused (`VkTableIdentityMismatch`, `VkTableLogsMismatch`, `VkTableBoundMismatch`);
- the authority is born retired: it can verify, never prove.

`Prove.verify` reads only the root, FIXED logs, tree logs, identity, `n_outputs` and the bound AIR, so verification under
the compact key is the same function as under a full authority. Derive checks this on every block: the root-only
self-check must reproduce the full receiver's root digest and authority (`RootOnlyAuditDisagreement` otherwise).

## 3. Why root-only is sound for today's format (`rv64-m4-fold-v2-compat/v0`)

The fold v2 note (`rv64-m3-topo-binding.md`) proves, per fold: if the fold proof verifies under the receiver's fold
authority for class (S_L, S_R) and its outputs equal `expectedDigest(A_L, A_R, o_L, o_R)` computed from the receiver's
child authorities, then each child proof was verified **in-circuit** against exactly the receiver's child identity, FIXED
root and structure, with outputs o_x, except with a Blake2s collision.

Induction over the tree: apply the lemma at the root with the receiver's table keys, then at each child with the same
keys. The receiver recomputes every o_x itself: fold outputs are its own recomputed digests, leaf outputs are
`Blake2s(words)` of the leaf frame words, computed from the receiver-admitted bundle exactly as `execution_wrap.runImpl`
does. So one accepted root proof implies that every leaf proof was verified in-circuit under the receiver's leaf key with
the receiver's words, which is what today's full receiver establishes by verifying each proof separately. Folding the
lemma costs one collision bound per fold (≤ 255 folds, each ≈ 2^-128, unchanged from the fold v2 accounting).

Receiver-side checks kept (no in-circuit home before M5, binding note §9.2): `expectedFromRequests` (genesis, adjacency,
steps), `services_root.check` (inventory and image-memory admission via `P.admit`, manifest reconstruction, CPU/truth
frames, public RAM, separate RAM/KIO/Wire closure), `terminal.require` (block output). Removed: native proof
verification (in-circuit in the leaf) and child recursion verification (in-circuit in the fold).

The tree shape is the receiver's own (streaming binary carry, rightmost-upward finalization, `expectedRoot`), and adjacency
is checked at every combine, as in `runImpl`.

### 3.1 Table keys and the one premise

- **Fold** entries are keyed by `om31_outer.classKey` (re-implemented over compact keys; derive cross-checks the
  re-implementation against the circuit code on every fold it builds, `VkFoldClassReimplementationDrift`, and the digest
  likewise, `VkFoldDigestReimplementationDrift`). "Fold topology = f(classKey)" is the fold v2 claim, already tested.
- **Leaf** entries are keyed by `leafKey` = SHA-256 over: leaf kind/family, the producer declaration JSON the receiver
  re-derived the native setup from, the receiver's native FIXED binding (source root, fixed identity, fixed root, native
  profile), the PCS config, the outer protocol domain.
  **Premise:** a leaf's topology (hence PP, FIXED root, identity) is a function of that key; every per-segment statement
  value is a guessed frame word hashed into the leaf output, not a circuit constant.
  - Evidence [M]: 3 truth leaves have byte-identical authorities across 26235156 and 24628607 at different ordinals and
    statements; the merged table has 1 shared leaf class (the key is deliberately over-specific: it includes the
    declaration, so the other 2 equal-authority leaves got separate entries).
  - Derive enforces the premise on every repeated key (`VkLeafClassMismatch`).
  - **If the premise were false**, the table key would hold an honest leaf circuit of the same native class but another
    segment. The root then binds the producer's leaf to that circuit (fold lemma). The producer's proof was made under its
    own leaf circuit, so the honest root digest differs and root-only **rejects** (a completeness failure, not a soundness
    one, for honest producers). A cheating producer would need a leaf proof under the receiver's circuit with the
    receiver's words. That circuit is an honest native verifier for the same native VK, so this is soundness of that leaf
    circuit, but for a circuit derived from a different segment. That is why `--audit` stays the **acceptance** path for
    this compat profile, and root-only is labelled engineering in its stdout `acceptance_scope`.
  - M5 canonical leaves remove the premise: `R_leaf[f, r]` is constant by construction.

### 3.2 Receiver policy (what is never producer-chosen)

- **Table provenance:** the table header pins schema, table profile id, native profile label, outer protocol domain,
  fold message version, the program identity of the request's image, and `receiver_sha256` = sha256 of the deriving
  binary (`/proc/self/exe`). `verify-root-candidate` refuses any table not derived by the very same binary
  (`VkTableNotDerivedByThisReceiver`). The source commit is recorded for humans.
- **Unknown profile ids are refused** (`UnknownVkTableProfile`). `rv64-m5-canon/v1` is named and reserved; it is refused
  (`VkTableProfileNotImplemented`) until canon-vk's format exists.
- **Store-supplied VKs are refused:** a table at or under the proof directory is rejected before it is read
  (`StoreSuppliedVkRefused`). Derive never reads the ArtifactStore or a setup cache (`STWO_ZIG_RV64_SETUP_CACHE` set → refuse).
- **Integrity:** `table_root` = Blake2s over the canonical sorted entries and header ids; it is recomputed on load
  (`VkTableRootMismatch`). It is an integrity check of a receiver-local file, not a trust root.

## 4. Measurements [M] (single observations, pod load 27–35, so not quotable as best-so-far)

Proofs: M4 integrate binaries (`a9acb639`), byte-identical format, both dev blocks proved once each into
`/workspace/m3/runs/m5-rootverify/*-m4base`. Receiver `48ba61f9…` built from this branch.

| block | today's receiver (M4 binary, harness receive) | `--audit` (this binary, full tree + root-only) | **root-only verify per block** | of which root proof | one-time derive |
|---|---:|---:|---:|---:|---:|
| 26235156 | 43.2 s (load 13–25) | 46.0 s | **10.1 / 10.1 s** (2 runs; 9.8 in-process) | 14 ms | 39.2 s |
| 24628607 | 63.7 s (load 13–25) | 57.8 s | **14.6 / 14.9 s** (2 runs; 14.3 / 14.6 in-process) | 14 ms | 52.4 s (59.0 s merged) |

Root-only breakdown on 24628607 (s): native keys 8.17, native FIXED authority 5.00, admission (inventory + manifest +
frames + closure) 0.87, image/program 0.36, bundle load 0.12, self sha 0.05, table load 0.0003, root tree 0.0001,
root authority 0.001, decode 0.001, **OM31 root verify 0.012**.

**Gate status: not met (≤ 1.5 s).** 13.2 of the 14.6 s on 24628607 [D] is native setup that today's receiver-side
admission needs: `CpuSetup` plans and native FIXED bindings for the frame words and `services_root.check`. The verifier
work proper is 14 ms. In M5 that native setup leaves the receiver, because:
- native VKs become T_nat entries (canon-native §3), derived once;
- the per-segment admission becomes in-circuit leaf constraints (binding note §3.2(7), §9.2).

The M5 per-block receiver is then table load + statement recompute + one root verify: about 0.1 s [E]. Until then, the
lever inside today's format is a receiver-derived native table (§6).

## 5. Negative corpus (root-only)

`scripts/rv64_m5_rootverify_corpus.py` runs every runnable case of `rv64_m5_negative_corpus.py` against
`verify-root-candidate`, plus 15 table/profile cases (`RV01`–`RV15`): store-supplied table, unknown and unimplemented
profile ids, other receiver, other image, native profile, leaf/fold VK root, identity and log tampering (root re-sealed so
the semantic check, not the integrity check, must reject), missing leaf/fold classes, an unsealed tamper, a table derived
only from the other dev block, and swapped leaf VKs.

Cases that mutate bytes the root-only receiver never consumes are `reject_or_same_statement`. These are child recursion
proofs (S02, S04, S06, V01–V03, R06), native proof bodies with a re-hashed bundle (R07–R09) and producer tree metadata
(K01, K03). Accepting them is a pass only with the control's exact statement (output, root digest, root identity,
profiles): the root proof attests to in-circuit verification, so on-disk child bytes cannot change what is accepted.
Result [M] (receiver `48ba61f9…`, table `vk-table-dev-blocks.json`): **51/51 pass on both dev blocks.** All 37 cases that
must reject do reject, with no crash and no non-semantic reject. The 14 accepted cases (C00, K02 and the 12
not-consumed cases) carry exactly the control's statement. Receipts: `vectors/reports/rv64-m5-20261104/rootverify/*-rootonly-corpus.json`.
A first corpus pass found a harness bug, not a receiver bug: RV15 v0 swapped two leaf VKs that 26235156 does not use, so
it was accepted with the control statement. RV15 now rotates every leaf VK.

## 6. Next levers (in order)

1. **canon-vk format** (`rv64-m5-canon/v1`): parse the root's NS (binding note §2) and run receiver checks §5(3). The
   table rows become T_rec/T_nat entries; the derive hook stays as it is.
2. **Native VK table for today's format:** record (source root, fixed identity, fixed root) per native class and admit
   bindings from it instead of recomputing native FIXED commitments (−5.0 s on 607 [D]). This needs a verifier-only
   constructor for `fixed_authority.Binding` (owner: canon-native / setup_cache).
3. **Light native setup for receivers:** admission needs geometry and plans, not FIXED witness columns (−8.2 s on 607 [D];
   `keys.zig` is canon-native's).
4. **Parallel `--audit`:** the full-tree path is sequential (1 s PP + FIXED per node, 33 nodes) and is the derive cost;
   a node-parallel DAG on 48 cores bounds it by the tree's critical path (about 6 nodes) [E].
