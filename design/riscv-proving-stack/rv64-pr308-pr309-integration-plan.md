# Integrating PR308 guest/services into PR309 GKR

Snapshot review,2026-11-02. PR308 is still developing; this document freezes a review point, not its final guest or a production merge.

## Checked merge and compatibility

| Item | Snapshot/result |
|---|---|
| PR309 | `f521aa1c1dc992d4e6224b54feca9fc25c48dc6a` |
| PR308 | `2490495dd16a35a2961cd113870a0a490ff36018`, `codex/rv64-guest-efficiency` |
| Common ancestor | `4d9aafacdc1ff7348aa5267d51c67e2b7e020c24` |
| Additional changes on PR308 |477files,230commits on its side of the divergence; GitHub's initial file/commit response was truncated at100, so scope comes from the fetched git tree |
| Trial merge | `3b11d94d79df5074c3407fb8a1bb22cd2617e7dc`; no textual conflicts; followed by compatibility fix`06f1c3ee6` |
| Isolated checkout | `/private/tmp/stwo-rv64-pr308-integration`, branch `codex/rv64-pr308-integration-review` |
| Combined focused checks | `test-riscv64-services-gkr-local` and `rv64-word16-ethereum-gkr` ReleaseFast pass |
| Existing complete GKR bundle | Initial merge rejects with`InvalidSumcheck`; after fix`06f1c3ee6`, fresh reception accepts25CPU+5truth proofs and the expected43-byte output |

Six files were independently edited on both sides: `build_support/products/riscv_cpu.zig`, Ethereum `gkr_main.zig`, and GKR `coordinator.zig`, `cpu_worker.zig`, `cpu_worker_test.zig`, `retention_plan.zig`. Git merged them automatically. Compilation/tests pass, but fresh old-bundle reception exposed a binary statement-encoding regression: two appended false geometry flags enter recursive field hashing even though JSON omits them. Fix`06f1c3ee6` freezes the16pre-v3 geometry fields in their original order. The rebuilt receiver now accepts the old complete bundle. The failed-before/passed-after logs and patch are committed under `vectors/reports/rv64-pr308-integration-review-20261102/`. This fix can be cherry-picked into PR308 without importing the trial merge. This is not v3-GKR qualification or a new performance measurement.

PR308 **does touch GKR integration code**, chiefly to preserve v2 compatibility and reject unsupported additions. Its `services/gkr_local/v2_scope.zig` rejects every v3 family, bulk/sponge/JUMPDEST components, LS-D64, fused-tail/U8-pair CPU layouts and throughput Keccak. These checks must stay until each replacement path is authenticated. Removing them or expanding an enum loop is not an integration.

## Scope and reuse

| PR308 work | Current GKR compatibility | Integration needed |
|---|---|---|
| evmone guest, host adapter, trie/runtime improvements | Admitted v2 build uses existing Keccak/secp ABI | New ELF/input identities and ABI symbols; execute, prove and verify with current OM/GKR route |
| SHA256 family3; arith256_mod family4 | Classic services lane supports them; OM/GKR refuses them | OM31 truth wrappers/challenges/claims; bridge local projections and Wire35/global mass; fixed authority and wire/manifest dispatch |
| Curve/field families5..11 | Classic services lane supports them; OM/GKR refuses them | Same authority chain per operation; exercise BN/BLS-bearing inputs, not only the benchmark block |
| memcpy/memset/unaligned memcpy/memcmp; JUMPDEST | CPU-proof components, no independent truth proofs | Typed origins, local fraction emitters, global RAM/OWNER closure, metadata/point projections and bounded source/ownership accounting |
| Keccak sponge | CPU-proof components connected to Keccak IO | Raw local projections, RAM and KIO participants, manifest mass and exact stream/terminal binding |
| LS-D64 head/tail | New narrower MAIN row; unsupported by GKR | OWNER/RAM/range projections, independently sized roles, source/OODS authority and canonical-write induction |
| CPU fused-tail | Classic LogUp INTER optimization; MAIN unchanged | Do not count its classic INTER saving in GKR, which replaces that trace already; initially select the historical compatible layout |
| CPU U8 pairs | Different local tuples and second AND multiplicity column | Explicit pair-tuple relation semantics and table/source binding; cannot reuse the old three-coordinate AND projection blindly |
| Throughput Keccak truth | Same MAIN/direct constraints; new tuples/tables/identity | OM31 policy-aware truth shapes and lookup authority; account for chi log21/xor log16, fixed trees, sampler and provider mass |
| Additional packed GKR prover | Prototype/benchmark implementation | Keep PR309 production kernels: PR308's own comparison finds no significant advantage and its alternative lacks streamed/checkpoint production paths |

The new AIR equation emitters often already accept typed scalar/packed/circuit lanes. Reuse those constraint authorities; do not duplicate truth equations in a new prover. Their native component wrappers are still QM31-specific in places, so generic equations alone are not OM31 proof integration.

## Ordered engineering slices

1. **Freeze and merge the final PR308 snapshot once ready.** Keep the current isolated trial branch while its remaining work lands; include compatibility fix`06f1c3ee6` in the final PR308 merge. Fetch its final head, merge the delta, repeat focused build/admission checks and v2 proof/receiver parity. Preserve PR309's streamed/deferred/owned paths and assumption-target reporting. Do not cherry-pick230already-integrated commits. Published PR309 has not imported this developing source snapshot.

2. **Qualify the admitted evmone v2 client on the existing GKR route.** `client_evmone/build.py --profile admitted` selects `ethereum_services_v2`; it can obtain guest instruction reductions without v3 adapter work. Derive heap/input/output/terminal symbols from that ELF, use its validated adapted input and expected output, run fresh execution agreement, then prefix and complete OM/GKR proof reception. Recalculate the security budget for its new roster. This is the shortest useful guest+GKR milestone, not the final v3 destination.

3. **Add v3 services under an explicit new GKR-services identity.** Preserve accepted v2 transcripts. Start with conservative compatible CPU/LS32/compact-Keccak geometry so interaction-layout experiments do not block the new guest. Port SHA/arith/curve truths, shared bridge kinds and the bulk/sponge/JUMPDEST CPU roles. Keep new truths in independent OM31 classic PCS initially, as existing truth proofs already do; converting their local lookups to GKR is not required to execute the new guest. Every enabled kind needs receiver-derived shapes, typed local/global projections, physical-root binding, claim closure, characteristic bounds and bounded witness custody. Unsupported kinds must continue to fail closed.

4. **Port representation wins separately.** Add LS-D64 first for MAIN reduction; then policy-aware throughput Keccak and U8-pair queries where measured worthwhile. CPU fused-tail's classic INTER gain is not a GKR gain. For U8 pairs, update both CPU query and table multiplicity authority. For throughput Keccak, independently size its larger tables and include their fixed-tree/setup and opening costs. Select layouts from receiver-owned capabilities; do not silently drop service calls or pass producer geometry through as authority.

5. **Qualify the complete new guest and regenerate the assumption budget.** Tiny per-family OM fixtures plus balanced/cross-shard/tamper cases precede one exact prefix and one complete pinned block. Compare public execution/output and fresh acceptance; new guest/protocol proof bytes are expected to differ. Preserve byte parity only for unchanged v2 paths. Exercise all enabled families across the basket, including curve calls absent from block24,628,607. Re-run final-client EEST as PR308 already lists as outstanding.

6. **Freeze the accepted v3 OM/GKR shape for GPU implementation.** Profile source construction, proving, fixed setup, stage cells/padding, memory and receiver work on the actual complete candidate. Device kernels must follow that field/transcript/shape authority. Recursion is a separate current-profile leaf/root task, not supplied by existing legacy RV64 recursion or v3 truth-leaf scaffolding.

## Security, measurements and moving-head caveats

The current native classification is [128-bit security target under documented assumptions](rv64-native-128-assumptions-review.md). It does not automatically cover the new guest/services. The exact model deliberately pins30proofs and the old shape; its assertions must not simply be relaxed. Re-derive family-specific polynomial degrees, lookup support/mass, local/GKR/binding counts, maximum columns and samples, table domains and transcript scopes. Preserve exact raw-mod sampling bias and the explicit native-only work/security assumptions. Query/PoW parameters do not establish correctness of newly admitted writers or buses.

PR308 reports3.283instructions/gas and40,336committed bits/gas over its scored basket. Those are not measured GKR proving times. Its committed current-client execution receipt has about26.895M instructions for block24,628,607 versus PR309's104.254M, but exact newer cost evidence is a four-packet prefix. The older complete-v3 proof and the newer prefix qualify different guest/layout snapshots. Some receipts retain the earlier fused/pair failure before its fix, so final-head qualification must be recorded anew. That block has no BN/BLS calls; it cannot qualify curve providers.

The alternate `gkr_prover_fast` is documented as on par with production, materializes layers and lacks bounded streamed/checkpoint paths. Replacing the production engine would discard qualified memory behavior without a measured win. Any useful fused-kernel idea should be ported into the existing pooled engine after a controlled comparison.

No GPU execution is part of this review. The user can continue finishing PR308 on its branch; only a final head/build-manifest freeze is needed before the production merge and end-to-end qualification. The isolated trial remains available for implementation meanwhile.

## Authenticated bulk foundation checkpoint

The next slice shares one ordered raw tuple emitter between classic fractions,
local GKR and global RAM for all nine bulk/JUMPDEST kinds. It adds the physical
OM31 bulk component, durable RAM metadata retirement and receiver-derived v3
child domains/codec framing. Complete classic v3 re-proving preserves all15
artifact hashes; fresh legacy v2 GKR reception still succeeds. See
[the component design and remaining gates](rv64-v3-authenticated-bulk-gkr.md).
This is not a complete v3 worker/receiver integration: production admission
remains closed, including retention and the reviewed source-support model.
