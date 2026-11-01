# TASK: RV64 Ethereum guest efficiency (autoresearch)

**Make the RV64 Ethereum guest execute fewer instructions per gas on the pinned
mainnet basket, with exact outputs on every block.** Lower is better.

Read [PROGRAM.md](PROGRAM.md) for the direction, the evidence and the three
parts. This file is the operating contract for agents.

## The loop

```sh
B=autoresearch/guest_efficiency/bench.py
CACHE=/path/to/cache            # outside the repo; ~250 MB

# once
python3 -I $B prepare --cache $CACHE --fetch      # pinned fixtures -> canonical inputs, host-validated
python3 -I $B build-exec --out $CACHE/exec        # execution-only RV64 tool

# every iteration
python3 -I $B build-guest --out $CACHE/elf        # 16 MiB window, ethereum-services-v2-lean
python3 -I $B run --elf $CACHE/elf/ethereum-rv64-services-v2-lean.elf \
    --executor $CACHE/exec/bin/rv64-ethereum-execution --cache $CACHE \
    --out $CACHE/runs/<name> --set scored --jobs 4 --keep-profiles
python3 -I $B attribute --elf $CACHE/elf/ethereum-rv64-services-v2-lean.elf \
    --execution $CACHE/runs/<name>/blocks/24628607/execution.json --out attr.json

# before you claim anything
python3 -I $B run ... --set all                   # all guards, including holdout
python3 -I $B check-scope --base origin/codex/rv64-arith-memory --include-worktree
python3 -I autoresearch/guest_efficiency/test_bench.py
```

Iterate on `--set scored` (12 blocks). A claim needs `--set all` (15 blocks):
the 3 holdout blocks must improve too.

## Scores

- **Primary:** `metrics.scored.instructions_per_gas`. Exact; no timing noise.
- **Co-metric:** `metrics.scored.committed_bits_per_gas`, a frozen proxy
  ([calibration.json](calibration.json)) that rewards fewer instructions and
  fewer Keccak/secp service calls in proportion to what they cost the prover.
- **Levels:** [targets.json](targets.json). Baseline 13.88 instructions/gas,
  then L1 8.61, ZisK committed-bits parity 8.32, ZisK reth parity 6.38,
  ziskethone parity 2.02, supersede 1.50.

Wall-clock execution time is not scored.

## Guards (all must pass; `run` exits non-zero otherwise)

| Guard | Rule |
|---|---|
| G1 complete basket | every block of the requested set ran |
| G2 exact output | executor completed and the 43-byte output equals the host-validated expected output |
| G3 determinism | the first block, run twice, gives identical counts and output |
| G4 per-block regression | no block more than 2% worse than its frozen baseline |
| G5 holdout generalises | holdout must not regress and must gain at least 50% of the scored gain |
| G6 execution profile | `ethereum_services_v2` only (Keccak-f and secp add/double services) |

## Scope

[scope.json](scope.json), checked by `check-scope`:

- **Editable:** guest code (`ethereum/rv64/src`, `mem/src`, `vendor/`,
  `Cargo.toml`), dependency files (review required), a new client directory
  (`ethereum/evmone/` or `ethereum/client_*/`; licence check required), and
  `ledger/`, `proposals/`, `notes/` here.
- **Locked:** this harness and its data, linker scripts, target spec,
  `service_abi/`, `build.py`, the projection and host-validation tools, all of
  `src/`, `build*`, `vectors/`.

## Rules

1. **Never special-case the basket.** No block numbers, hashes, addresses or
   fixture-derived constants in guest code. The holdout guard exists to catch
   this; reviewers will reject it regardless.
2. **Keep the public output and service ABI identical.** Anything that needs a
   new ECALL service, a different output or a larger input window is a
   proposal under `proposals/` (see PROGRAM.md "Out of scope for the loop").
3. **No host hooks or hints.** The guest must compute everything it outputs; no
   unverified prover-supplied answers.
4. **Correctness is soundness.** A faster but wrong EVM produces valid proofs of
   false state transitions. Every change must keep exact outputs; client
   replacements also need the EEST corpus and differential tests (PROGRAM.md).
5. **Licences:** do not copy third-party code (evmone, ziskethone, or others)
   until its licence is recorded and legal has signed off.
6. **Record every attempt** in `ledger/` as one JSON line: date, branch, commit,
   ELF sha256, result path, scored/holdout/all metrics, guard status, a one-line
   description, and whether it was kept. Failed attempts are evidence too.

## Promotion (human)

A kept result becomes the new baseline only after: all guards on `--set all`,
`check-scope`, unit tests, a Word16 prefix proof plus fresh `verify-prefix` on
block 24,628,607 with the new ELF, and review. The baseline in `basket.json` and
`targets.json` is then updated in a separate, reviewed commit.
