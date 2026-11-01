# evmone client, pass 2 (2026-11-02)

Branch `codex/rv64-ge-interp` (client track of the RV64 guest-efficiency
program). Client: `autoresearch/benchmarks/guest_runtime/ethereum/client_evmone/`.
Every number: `bench.py run --set all`, input adapter on, executor
`~/Coding/ge-cache/exec` (merged head), all guards G1-G6 pass, exact outputs
on all 15 blocks. v3 = `build.py --profile v3` (default `sha,arith,mem`,
aligned memory only), profile `ethereum_services_v3` (promotable).
Candidate = `--profile candidate --candidate-set mem,sha,arith,bn,bls,keccak`,
profile `ethereum_services_v3_candidate`, scored with the estimated costs of
`proposals/candidate-service-costs.json` + `candidate-curve-costs.json`
merged in memory (calibration.json has no candidate entries).

## Result

| | v3 scored instr/gas | v3 bits/gas | v3 all | candidate scored | candidate bits/gas | candidate all |
|---|---:|---:|---:|---:|---:|---:|
| Start (`4e4b38a62`) | 4.7776 | 67,192 | 4.6360 | 3.3944 | 55,556 | 3.3009 |
| End (`a40e9de1c`) | 4.5382 | 64,578 | 4.4006 | 3.3866 | 54,988 | 3.2936 |

The candidate-profile baseline passes G2 (exact output) at the start head;
the earlier "candidate baseline failed exact output" flag from the
interpreter2 track does not reproduce here.

Change: v3 -5.0% scored instr/gas, -3.9% bits/gas (holdout 4.061 -> 3.841);
candidate -0.23% instr/gas, -1.0% bits/gas. Ledger: 24 lines in
`ledger/attempts.jsonl` (branch `codex/rv64-ge-interp`).

## Kept steps (in order)

| Commit | Change | v3 scored | candidate scored |
|---|---|---:|---:|
| `6ba5cf8cf` | memory functions: 32-byte funnel copy, word heads/tails (memset, service splits), service threshold 16 -> 64 | 4.7776 -> 4.7507 | 3.3944 -> 3.3940 |
| `6e03231ff` | contract codes hashed while copied into ZEG0 (one pass; patch 0025 carries the digest in the record); unrolled absorb | 4.7507 -> 4.7135 | 3.3940 -> 3.3943 |
| `dc23ce427` | blst `mul_mont_n` with constant limb count (patch 0026) | 4.7135 -> 4.5942 | unchanged |
| `fc9a11863` | word copies at hot bytes32/address sites in ziskethone (patch 0027) | 4.5942 -> 4.5746 | 3.3943 -> 3.3918 |
| `c4e3fa1f0` | secp glue: 96-byte point copies inline | 4.5746 -> 4.5596 | 3.3918 -> 3.3916 |
| `a40e9de1c` | no loop-idiom memcpy in the SHA-256/Keccak glue; merkleize digests word-copied (patch 0027) | 4.5596 -> 4.5382 | 3.3916 -> 3.3866 |

## Measured, not kept

| Attempt | v3 scored | candidate scored | Why |
|---|---:|---:|---|
| Translated segments (parked `wip/0024`, was wip/0023) re-applied on the current stack | 4.778 -> 5.063 | 3.394 -> 3.680 | dispatch 1.116 -> 0.835/gas but xtranslate 0.47 + xinsert 0.07/gas |
| memcpy service threshold 16 / 32 / 128 (vs 64) | 4.7649 / 4.7630 / 4.7860 | - | 64 best on instructions and bits |
| fused copy+hash without unrolling | +0.048/gas | - | 13 instructions per word |
| memcpy fast path for 8-aligned n < 64 | +0.0016 | +0.057 | the call is the cost; candidate loses its cheap service |
| non-trivial copy constructors on evmc::bytes32/address | - | - | breaks ziskethone's trivially-copyable NodeR variant |
| blst outer loop also fully unrolled | 4.5942 -> 4.6313 | - | register spills |
| JUMPDEST scan skip table for 0x5b..0x7f | 4.5596 -> 4.5650 | 3.3916 -> 3.3973 | table load + merged tails = the arithmetic it replaced |
| inline Storages::value_at / Accounts::balance_at / code_hash_at | 4.5382 -> 4.5358 | 3.3866 -> 3.3884 | mixed (candidate worse); not kept |

## Interpreter pass 2: why the translator was not finished

Re-measured on the current stack, the parked translated-segment dispatch
still loses 0.26/gas (all blocks). Its ceiling is about +0.09/gas with an
ideal ~15-instruction-per-op translator, because each unique (code, pc) op
runs only ~4.5 times per block. Two other ideas were checked with data
before any code:

- Lazy JUMPDEST analysis (scan only up to the highest jump target used):
  host instrumentation on all 15 blocks shows the highest validated target
  is at 89% of the code size on average (e.g. 4.38 of 4.90 MB on 24628590),
  so at most ~11% of the 0.265/gas scan could be saved, less the bound
  checks. Not pursued.
- Per-opcode overhead in `dispatch_cgoto` (1.116/gas, 28 instructions per
  dispatched op): PUSH1 is 16 instructions (5 dispatch, 2 gas, 1 overflow,
  4+2 word build, 2 pointer bumps); the remaining single-instruction trims
  (e.g. not storing limb 0 twice) are ~0.005/gas each.

The interpreter bucket is therefore left at ~1.96/gas (dispatch 1.12,
JUMPDEST 0.27, handlers/intx/host thunks); the program's ~1.0 target needs
either Zbb (`rev8`, `sh3add`) or a different execution model, not
dispatch tuning.

## Where v3 instructions go now (all 15 blocks, per gas)

dispatch_cgoto 1.116, ethash_keccak256 0.362, analyze_into (JUMPDEST)
0.265, blst mul_mont_n 0.213, copy_forward 0.212 (misaligned copies: trie
encodings, calldata, receipts), stwo_keccak256_copy 0.104 (contract code
hashing), arith256_mod glue 0.097 (BN254 Fq2 products: ~54 instructions per
call around the service), secp double_mul 0.092.

## Tests added

- `tests/keccak_copy_test.cpp`: fused copy+hash vs ethash_keccak256, 0..700
  bytes x 8 alignments, destination contents and no overrun, keccak("").
- `tests/mem_fuzz.cpp`: the service head/body/tail split (split_copy,
  split_fill) with the body contract (8-aligned, nonzero multiple of 8).
- `tests/jumpdest_scan_test.cpp`: the guest-only sentinel scan vs evmone's
  reference scan on 200k codes (a PUSH-skip mutant is caught).
- `tests/xlat_difffuzz.cpp` runs without the parked patch (fused vs plain).

## EEST

Not re-run: the EEST cache (fixtures tarball 939 MB, the `stateless`
workspace and its reth build, ~10 GB of inputs) does not exist on this host
and the disk had 7-14 GB free with a 1.5 GB scratch cap. The three liveness
bugs are already fixed on the merged branch (blst 0002 quot_rem; row_reserve
from gas_used, which also fixes the 7702 depth case); `build.py --host
--tests` (blst portable == assembly, 114 results) passes on every kept step.
Affected groups to re-run when space allows: eip2537 (BLS, patch 0026),
eip4844 point evaluation (KZG, patch 0026), any group (memory functions,
patches 0025/0027 touch every block).
