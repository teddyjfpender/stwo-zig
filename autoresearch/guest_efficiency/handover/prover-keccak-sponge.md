# Handover: admitted Keccak-256 sponge (prover), 2026-11-01

Branch `codex/rv64-guest-prover-keccak-sponge` (worktree
`/private/tmp/stwo-rv64-guest-prover-keccak-sponge`), based on the finished
v3 integration (`origin/codex/rv64-guest-prover-v3-integration` b25175ff6,
merged in 6e6c95992). Paused on user instruction.

## Done and verified

| Item | Evidence |
|---|---|
| Admitted executor, tag `0x0003_0130` in `ethereum_services_v3` (`src/frontends/riscv/rv64/ethereum_services/keccak_sponge.zig`): any input alignment, len < 2^20, finalize/fresh flags, no empty non-final call, state rights 3, packet/state/message words disjoint, traps change nothing | `zig build test-riscv64-execution` passes: Keccak-256 for lengths 0..559 x 8 alignments, split absorb+finalize, empty message, every trap; v3 session dispatch, v2 traps |
| Frontend plumbing: tag, `isPayloadFreeTag`, session arm, payload-free tape record (no tape wire section, like bulk), boundary capture, census, report counters | same suite |
| Bridge AIR `src/frontends/riscv/rv64/air/delegations/keccak_sponge/` (call row 694 MAIN / 380 INTER / 325 constraints; perm row 973 / 688 / 1,025) | `zig build test-riscv64-keccak-sponge`: honest 5-call scenario closes RAM/OWNER/IO/AND/ranges; 23 lengths x 8 alignments match std Keccak-256 and close; 8 adversarial cases rejected (wrong XOR, wrong byte, skipped/reordered blocks, forged final state, length mismatch, forged padding/fresh state, non-canonical tail byte); degree <= 3 |
| Services lane (roster block after bulk, shared Keccak IO11 IDs after all Keccak-f calls, per-shard `sponge.first_id` checked in `admit`, AND-table merge, transcript/claims/wire blocks only when present) | `zig build test-riscv64-word16-sponge-services -Doptimize=ReleaseSafe` passes (commit 7709689fe): 2 shards, real STARKs, fresh receiver over the wire, split truth spans; wrong truth input -> UnclosedCombinedKeccakIo; forged/stale message -> UnclosedCombinedRam; missing bridge, short span, wrong first ID, nonzero absent claim rejected |
| Docs | `design/riscv-proving-stack/rv64-keccak-sponge-service.md`, section in `src/integrations/riscv_cpu/word16_global_execution/soundness_review.md` |

## Written but NOT verified (compiled only as far as noted)

- Driver: `ethereum/plan.zig` (sponge logs, Keccak truth totals include sponge
  perms), `ethereum/main.zig admitProfile` (`UnadmittedKeccakSpongeService`),
  `rv64_ethereum_batch.zig` / `rv64_work_packet_admission.zig`
  (`isPayloadFreeTag`). Compiled into nothing tested yet; no Ethereum block run.
- AND-table receiver mass check in `services/protocol.zig admitSponge`
  (added after the last passing services run; not compiled).
- evmone client: `glue/keccak_stwo.cpp` `ADMITTED_KECCAK` path and
  `build.py --v3-set ...,keccak`. Not built, not run.
- `role_cost.zig` / `telemetry.zig` have no sponge rows (cost telemetry gap).

## Not done

1. Regression: v2 combined services, bulk, v3 all-services, word16-execution-prepared,
   global-execution suites have NOT been re-run on this branch.
2. v2/SHA-only/v3 fixture bundle byte identity vs base b25175ff6 NOT checked.
   Script prepared (not run): scratchpad `prover-keccak-sponge/ident.sh`
   (builds `rv64-word16-combined-services-fixture` at base and branch, produces
   `produce` and `produce-v3` bundles, cross-verifies, diffs).
3. Cost measurement: only nominal cells (call 1,074; perm 1,661 cells/row,
   plus the unchanged Keccak-f truth ~72k per permutation). No measured
   per-call/per-block numbers, no calibration.json `admitted_services` entry,
   no bench run.
4. Recursion: no sponge role in om31/circuit lanes.
5. Throughput-table Keccak AIR (cost design option (a)): not started.

## Known issues / risks

- Wide perm row (973 MAIN): packed_rows uses heap scratch; interaction
  generation is scalar QM31 per row (slow at large logs, unprofiled).
- `mask` (136 cols) is paid on every perm row; a separate final-row component
  would cut ~8% of perm cells.
- Debug builds of the services suite may overflow worker stacks (as bulk); use ReleaseSafe.

## Resume

```sh
cd /private/tmp/stwo-rv64-guest-prover-keccak-sponge
lockf -k /private/tmp/stwo-rv64-perf-build.lock zig build test-riscv64-keccak-sponge test-riscv64-execution -j3
lockf -k /private/tmp/stwo-rv64-perf-build.lock zig build test-riscv64-word16-sponge-services test-riscv64-word16-v3-services test-riscv64-word16-bulk-services test-riscv64-word16-combined-services test-riscv64-word16-execution-prepared -Doptimize=ReleaseSafe -j3
# byte identity: recreate a base worktree at b25175ff6 (git worktree add --detach <scratch>/base b25175ff6) and run ident.sh
```
