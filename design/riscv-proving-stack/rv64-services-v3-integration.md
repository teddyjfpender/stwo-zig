# `ethereum_services_v3` integration: SHA-256 + arith256_mod + bulk memory

Branch `codex/rv64-guest-prover-v3-integration` merges the three admitted v3
prover services into one profile and proves the evmone client end to end.
Service designs: [SHA-256](rv64-sha256-service.md),
[arith256_mod](rv64-arith256-service.md), [bulk memory](rv64-bulk-memory-service.md);
merge rules: [extension points](rv64-services-v3-extension-points.md).

## Merges and reconciliations

| Merged | Resolution |
|---|---|
| `origin/codex/rv64-guest-efficiency` | Executor profile enum carries the execution-only `..._candidate_isa` and admitted `ethereum_services_v3`. |
| `codex/rv64-guest-prover-arith256` | Tape: arith records moved after the SHA-256 records into a v3 extension flagged by bit 31 of header word 28..32, present only with arith calls (SHA-only v3 tapes keep their bytes); work-packet budget/admission follow. Planner arith span count made an explicit u32. |
| `codex/rv64-guest-prover-bulk-memory` | Family 4 / Wire35 kind 4 stay arith256_mod; bulk stays a separate block after all families everywhere. Ethereum work-packet route extended to bulk (`admitsV3`, native batch, admission cell bound, cost roster rows, `admitProfile`). |
| `origin/codex/rv64-guest-prover-eest` | evmone EIP-7702 delegation-code and trie deletion-order fixes, merged before measuring the v3 guest. |
| Harness | One `calibration.json` `admitted_services` table (sha256_compress, arith256_mod, memcpy, memset; per call + per byte, status, derivation) mapped through `bench.py` `ADMITTED_REPORT_FIELDS`; `coefficients.sha256_cells_per_call` retired. |

One regression was found and fixed during the integration: the arith branch
mixed each present v3 family's CPU claims in its own `mixFelts` call, which
changed every SHA-only CPU transcript (SHA-only fixture CPU proofs differed and
failed cross-verification with `OodsNotMatching`). `CpuClaims.mix` now mixes
the v2 vector plus present v3 families in one call; bulk claims stay a
trailing call.

## Qualification

- Suites, all passing (ReleaseSafe): execution, sha256-truth, arith256-truth,
  word16-bulk-memory, word16-arith256-bridge, word16-arith256-services,
  word16-bulk-services, word16-v3-services (new), word16-combined-services,
  word16-global-execution, word16-ethereum-terminal, word16-keccak-shared,
  word16-keccak-bridge, word16-secp-bridge, secp, services-gkr-local,
  word16-execution-prepared, ethereum-packet-control, work-packet,
  ethereum-chain; `python3 -I autoresearch/guest_efficiency/test_bench.py` (40).
- v2 byte identity: `rv64-word16-combined-services-fixture produce` equals the
  `codex/rv64-guest-services-base` golden bundle in all seven files
  (`bundle.json` `be49c88c…`); the merged receiver verifies the golden bundle
  and the base receiver verifies the merged bundle.
- SHA-only v3 identity: `produce-v3 sha256` equals the SHA branch's output
  (same tool mode built on the SHA branch head) in all files; both receivers
  verify both bundles.
- All three services together: `services/v3_fixture.zig` executes a two-shard
  program on the real v3 session (SHA-256, arith256_mod, memset | memcpy of
  SHA-256's epoch-1 output, arith re-reading its r, LD, SHA-256). It proves and
  verifies in-process and with a fresh receiver over the wire
  (`produce-v3 all` / `verify-v3 all`); receivers missing any family's bridge
  or the arith truth reject; nonzero unused truth claims reject; false SHA and
  arith outputs fail Wire35 (`UnclosedCombinedSecpWire`), forged copies, fills
  and stale copy sources fail global RAM (`UnclosedCombinedRam`).

## evmone client on the admitted v3 profile

`client_evmone/build.py --profile v3` (`ADMITTED_SHA`, `ADMITTED_ARITH`,
`ADMITTED_MEM`): SHA-256 on the 32-byte aligned packet; MULMOD, ADDMOD and
256-bit `ModArith` through arith256_mod (patch 0004 guards), 256-bit
odd-modulus modexp through arith256_mod in plain form (patch 0023); aligned
memcpy/memmove/memset with inline head/tail, 1 MiB chunks, 16-byte threshold
and software fallback for overlap or mismatched alignment (as the Rust
`admitted-mem` feature). All 15 basket blocks, input adapter, exact outputs,
every guard passing, promotable
(`autoresearch/guest_efficiency/notes/evmone-v3-admitted-results-20261101.json`):

| Set | instr/gas (same-tree v2 → v3) | committed bits/gas (v2 → v3) |
|---|---|---|
| scored | 6.807 → 4.778 (−29.8%) | 86,044 → 67,192 (−21.9%) |
| holdout | 5.616 → 4.061 (−27.7%) | 71,350 → 56,829 (−20.4%) |
| all | 6.572 → 4.636 (−29.5%) | 83,144 → 65,146 (−21.6%) |

Basket service use: 198,819 SHA-256 compressions, 800,115 arith256_mod calls,
1,526,468 memcpy (158.3 MB), 496,811 memset (113.9 MB). Bits/gas use the
measured costs below.

## Block 24,628,607 with the evmone v3 guest

Native jobs (`rv64-ethereum-proof nativeprepare`, terminal pc 536,892): 9
batches, 36,659,069 instructions (Rust v2 guest: about 104M). Receipt:
`vectors/reports/rv64-ethereum-20261101/evmone-v3-block-24628607-v1.json`.

| Run | Result | Prove | Peak RSS | Fresh verify |
|---|---|---|---|---|
| 4-shard prefix | 4 CPU + 6 truth proofs | 32.2 s | 24.8 GB | `verify-prefix` accepted, 1.9 s, 2.2 GB; v2 request rejects (`UnadmittedSha256Service`) |
| complete block | 9 CPU + 6 truth proofs | 61.6 s (67.5 s first run) | 37.5 GB max RSS (24.5 GB peak footprint) | `verify` accepted, completed block, output matches, 4.6 s, 2.4 GB |

Committed cells of the complete block (exact padded, cost.json): MAIN +
INTERACTION 8.554 G (CPU 5.815 G, truths 2.739 G); with fixed columns 8.865 G.
The v2 baseline receipt (`optimization-current-baseline-v1.json`, Rust guest)
lists about 135.6 s prove median and 20.336 G cells. Default driver options, not the
baseline's 2x8 schedule; both runs shared the machine with other sessions
(load average about 15; the first also with this branch's test suites), so
the times are indicative, not a benchmark. Both runs produced identical
, and both bundles verify with a fresh .

Measured per-call costs (MAIN + INTERACTION, padded, from this proof; now in
`calibration.json`):

| Service | Measured | Derivation | Layout tier |
|---|---:|---|---:|
| SHA-256 | 12,615.4 / call | truth log12 30,380,032 + bridge 6,217,344, over 2,901 calls | 8,551 unpadded |
| arith256_mod | 4,460.3 / call | truth log9 455,168 + bridge 967,680, over 319 calls | 4,009.3 (1/ln 2) |
| memcpy | 154.3 / call + 15.152 / byte | desc 5,734,400 over 37,168 calls; copy 50,462,720 over 3,330,392 bytes | 161.6 + 13.886 |
| memset | 154.3 / call + 8.457 / byte | desc as memcpy; set 22,413,312 over 2,650,424 bytes | 161.6 + 8.656 |

## Remaining gaps

- Recursion circuits and `services/gkr_local` know none of the v3 families'
  bulk components (and no v3 truths in recursion), so a v3 bundle cannot be
  wrapped or folded yet.
- v3 remains a receiver policy (`admitProfile` + bridge presence), not part
  of the program identity; native jobs run v3 tapes under the v2-decoded ROM.
- Unaligned memcpy (the larger share of copies) is not admitted.
- Whole-protocol security accounting for the new lookup masses is not done.
- Licence review of the fetched evmone/ziskethone sources is still required
  before vendoring (client README).
