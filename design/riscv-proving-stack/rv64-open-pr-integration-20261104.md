# Open RV64 PR integration review — 2026-11-04

Reviewed against PR314 head `e5d977e0d`; PR316 was subsequently merged into this
branch as `3b116e722`. This was a read-only source review followed by focused
CPU tests, not a new GPU qualification or performance measurement. The
coordinator has confirmed a two-GPU host for subsequent qualification; this
review establishes no two-GPU throughput or scaling result.

| PR / pinned head | Recommendation | Scope and qualification |
|---|---|---|
| [316](https://github.com/teddyjfpender/stwo-zig/pull/316) / `59f3a28d7` | Retain the completed merge `3b116e722` | Adds balanced forged-claim, swapped-shard and omitted-truth negatives, restores/rechecks valid bundles, and corrects stale delivery notes. Runtime changes are comments; no AIR, transcript or proof-format change. |
| [320](https://github.com/teddyjfpender/stwo-zig/pull/320) / `298bb29ca` | Continue in a separate integration context; cache trust stays OFF | Persisted/resident setup and duplicate CPU source-key commit removal are relevant to cold setup. The merged PR head is explicitly not fully qualified. Preserve the current receiver's independent authority path until the cache trust boundary is resolved. |
| [306](https://github.com/teddyjfpender/stwo-zig/pull/306) / `f94150c77` | Do not merge wholesale | Most architectural scaffolding predates the implemented OM31 services/GKR/recursion path. Its useful security arithmetic is already integrated and strengthened here. A bounded independent RAM-flow reference remains an optional diagnostic port. |
| [321](https://github.com/teddyjfpender/stwo-zig/pull/321) / `ce11aff51` | Keep the tensor product separate | It is an unrelated frontend/PCS with broad additions. Shared CPU GKR/field changes need their own review and parity checks; they do not establish a resident RV64 GPU improvement. |

## PR316 checks on the integrated branch

Both guarded ReleaseSafe invocations passed on `3b116e722`:

```sh
zig build test-riscv64-services-gkr-local -Doptimize=ReleaseSafe -Driscv-test-filter='V3 GKR complete' -j2
zig build test-riscv64-services-gkr-local -Doptimize=ReleaseSafe -Driscv-test-filter='V3 GKR compact decode CPU' -j2
```

The first selects the three complete SHA/arith/bulk, D64 and sponge fixtures;
the second selects the compact-decode fixture. All four exercise the new
mutation helper and re-verify the restored valid bundle. Observed rejections
include `OodsNotMatching` for balanced/unbalanced forged claims,
`GlobalGkrPhysicalRootMismatch` for swapped shards, `InvalidSumcheck` for the
compact-layout mutation and `UntrustedGlobalGenesis` for the forged initial PC.
The omitted-truth case checks `InvalidWideServicesProofInventory` where truths
are present. These are focused tests, not a full-suite or new full-block run.
PR316's historical q256 receiver receipts remain distinct from this branch's
newer conjectured q108 default and its documented-assumption security target.

## PR320 integration gates

The exact integration commits are `aaec05991c4e`, receipt commit
`6f1e4871319e`, and main-merge head `298bb29ca`. Do not apply the earlier
`gkr_main.zig` wholesale: reconcile it with current resident sessions, GPU
source/replay hooks, bounded workers, policy-v2 boundary geometry and the
independent receiver/recursion paths. Existing in-process warm setup already
has validated binding/source ownership; retain those invariants.

`setup_cache.zig` restores source and fixed commitment roots from a disk VK
section. SHA checks detect corruption, but a party able to rewrite the file
can rewrite its digests too. An executable hash namespaces the cache; it does
not authenticate cached roots. Cache-directory write permission does not
necessarily imply permission to replace the executable. Keep
`STWO_ZIG_RV64_SETUP_CACHE` unset on independent receivers unless an explicit
trusted VK-storage policy or independently authenticated root manifest is
provided. Prover-only caching can be evaluated against a cache-disabled fresh
receiver. The current reviewed default remains cache-disabled.

Required integration checks: cold/warm complete and prefix proof-byte parity;
fresh cache-disabled receivers; changed program, geometry, sampler/profile,
input and cache-body cases; ownership after the first Image is destroyed;
resource/retention bounds; and preservation of current GPU hooks. The PR's
pre-merge M4 timings are historical evidence, not measurements of this branch.

## PR306 gaps and exact selective-port advice

The single-draw and conditional arithmetic already landed as `27d3d806b` and
`473c16f4e`. `1dff197ab` then added actual raw-modulo sampler-bias accounting.
Replacing the security-policy files with PR306's versions would remove
`requireRawModuloConditionalBudget` and its tests. Do not regress them or
infer a whole-protocol certificate from arithmetic-only budget predicates.

The optional unported reference is the final pair
`word16_execution/memory/global_flow_model.zig` and
`global_flow_model_test.zig` from `f94150c77`. Prefer copying those final files
into an isolated diagnostic change with explicit test-root registration over
replaying their many intermediate correction/temporary-CI commits. It is an
allocation-free 64-word/256-event model, deliberately unable to authenticate
CPU/service origin. Its collector adapter covers old LS/Keccak/secp records,
not the full modern V3 provider roster. It must not become a production verifier.

Leave the old staged precommit, native host certificates, QM31 host-fold
reference and temporary workflow out of this integration. They do not add the
current physical OM31 GKR/PCS bindings or succinct recursive root, and their
old boundary-log<=22 assumptions do not qualify policy-v2 boundary23 proofs.

## PR321 shared-code follow-up only

`b181b81eb` is a contained CPU GKR multi-instance barrier-batching candidate
worth a later isolated review, byte-parity test and CPU A/B. The resident CUDA
GKR path supplies its own numerical backend, so this is not a demonstrated GPU
speedup. The global QM31 multiplication rewrite `29c003858` and compiler-workaround
`bd2cd666d` must not be imported casually: the branch explicitly documents a
Zig0.15.2 ReleaseFast inline miscompilation. Any field-arithmetic adoption needs
property/reference tests and fresh existing-proof reception across affected
products. The tensor PCS, security model and frontend remain separate scope.
