# Handover: admitted Keccak-256 sponge (prover), 2026-11-02

Branch `codex/rv64-ge-sponge` (worktree `~/Coding/ge-wt/sponge`), from
`origin/codex/rv64-guest-efficiency` 4e4b38a62. Previous handover (branch
`codex/rv64-guest-prover-keccak-sponge`) is superseded by this one.

## Done and verified (2026-11-02)

| Item | Evidence |
|---|---|
| AIR + services suites | `zig build test-riscv64-keccak-sponge -Doptimize=ReleaseSafe` (19 tests) and `test-riscv64-word16-sponge-services` pass |
| Regression (ReleaseSafe) | word16-combined-services, word16-v3-services, word16-keccak-shared, word16-keccak-bridge, word16-global-execution, execution, ethereum-chain: all pass |
| v2 byte identity | `rv64-word16-combined-services-fixture produce` = golden in all 7 files (bundle.json be49c88c, cells c4162b24, cpu-0 8ae9b7a8, cpu-1 545877eb, truth 756461d3/0383740b/2ddb3fc9); verifies |
| SHA-only v3 identity | `produce-v3 sha256` at head = at pre-sponge base b25175ff6 (diff -r identical; bundle.json e97771c4); each receiver verifies the other's bundle |
| Soundness: joint write induction | design doc section 4.1 (sponge writer case: P1 clocks, P2/P4 atomic Boolean transitions, rights, ordering, written values anchored by Keccak-f truth bits through IO11); pointer in `rv64-ls-joint-write-induction.md` |
| Adversarial | skipped block, wrong XOR, reordered blocks, forged final state, length mismatch, padding/fresh-state forgery, non-canonical tail byte (existing) + new digest-write forgery (non-canonical written limbs with forged RAM env -> only IO11 rejects; byte split; redirected state pointer). Inverted-assertion check confirmed the test runs |
| evmone routing | `glue/keccak_stwo.cpp` `ADMITTED_KECCAK` (> 64 bytes; chunks < 2^20) built via `build.py --profile v3 --v3-set sha,arith,mem,keccak` (ELF ce85a9fd...) |
| Basket (15 blocks, all guards, exact outputs) | provable v3 scored 4.778 -> 4.426 instr/gas, 67,192 -> 64,114 bits/gas; holdout 4.061 -> 3.764; all 4.636 -> 4.295. Keccak glue 0.465 -> 0.108 instr/gas. `notes/keccak-sponge-admitted-results-20261102.json` |
| Costs | `calibration.json admitted_services.keccak_sponge`: 1,409.3 cells/call, 2,100.3 + 72,159.3 (truth) per permutation (planned geometry, complete block 26,235,156); confirmed by produced roster.json of its 1-packet prefix (1,494.7 / 1,988.6 on shard 0). bench.py counts sponge calls/bytes/permutations; test_bench 41 OK |
| Driver | `rv64-word16-ethereum` compiles again (plan.zig shadows, role_cost/telemetry for 12 families + bulk kinds + sponge rows). nativeprepare (block 24,628,607: 8 packets, completed; block 26,235,156: 5 packets) and a real 1-packet prefix proof of block 26,235,156 accepted by fresh `verify-prefix`; v2 request rejects |

## Not done

- Block 24,628,607 prefix/complete proofs with the sponge guest (coordinator; command below).
- Throughput-table Keccak AIR (-43% cells/permutation): not started. It needs a
  new RV64 truth component next to the compact one (tuples from
  `guest_precompile/keccakf_throughput_tables_v1.zig`), 2^21 chi and 2^16 xor5
  table components, re-derived lookup masses, truth keys/wire/receiver roster,
  adversarial tests; multi-week (design doc estimate 2.5 weeks).
- Recursion: no sponge role in om31/circuit lanes.
- `cost.json active[].sponge.first_id` prints 0 (counts() omits it; diagnostic only).

## Prefix-proof command for block 24,628,607 (coordinator)

From `~/Coding/ge-wt/sponge` at the branch head (binaries already built in
`~/Coding/ge-cache/sponge/head/bin`; rebuild with
`zig build rv64-ethereum-proof rv64-word16-ethereum -Doptimize=ReleaseFast --prefix ~/Coding/ge-cache/sponge/head`).
Request: `~/Coding/ge-cache/sponge/b607/request.json` (ELF
`~/Coding/ge-cache/sponge/evm/client-evmone-v3-sha-arith-mem-keccak.elf`
ce85a9fd, adapted input e549944d, v3, terminal_pc 536264, batch_steps 4194303).

```sh
cd ~/Coding/ge-cache/sponge/b607
B=~/Coding/ge-cache/sponge/head/bin
memguard run --gb 4 --label sponge-nprep -- $B/rv64-ethereum-proof nativeprepare request.json   # ~2.0 GB packets in ./native
memguard run --gb 24 --label sponge-prefix4 -- $B/rv64-word16-ethereum produce request.json native/jobs prefix4 4
memguard run --gb 4 --label sponge-vprefix -- $B/rv64-word16-ethereum verify-prefix request.json prefix4
# complete block: produce request.json native/jobs complete 0 ; verify request.json complete
```
