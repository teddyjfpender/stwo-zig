# TASK: RV64 Ethereum guest efficiency

**Make the RV64 Ethereum guest do far less work per unit of gas, with exact
outputs on every block.** Target: from 13.88 instructions/gas to 2.02
(ziskethone parity) and then 1.5. Lower is better.

This is an architecture program, not just a tuning loop. Read in order:

1. [CONTEXT.md](CONTEXT.md): what the prover charges for each instruction and
   service, how services are added, and the candidate-service ABI.
2. [PROGRAM.md](PROGRAM.md): the three moves (new client, new services, guest
   hygiene), their expected landing points, and the tracks.
3. This file: how to run, score, guard and record work.

## Two modes of work

- **Track work (architectural).** Large, multi-day changes owned by one track:
  a new client (move A), candidate services (move B). Design first, then build,
  then measure on the full basket. One result can move the score by 2-4x.
  Partial progress is recorded in `notes/` and `ledger/` even before it scores.
- **Loop work (incremental).** Small edits on a working client, scored in about
  two minutes each (move C). Use it once a track has a client that runs.

Do not spend loop iterations on the current client while a client replacement
is the bigger lever; record why if you do.

## Commands

```sh
B=autoresearch/guest_efficiency/bench.py
CACHE=/path/to/cache            # outside the repo; ~250 MB

python3 -I $B prepare --cache $CACHE --fetch      # pinned fixtures -> canonical inputs, host-validated
python3 -I $B build-exec --out $CACHE/exec        # execution-only RV64 tool (rebuild after executor edits)
python3 -I $B build-guest --out $CACHE/elf        # current Rust client, 16 MiB window

python3 -I $B run --elf <ELF> --executor $CACHE/exec/bin/rv64-ethereum-execution \
    --cache $CACHE --out $CACHE/runs/<name> --set scored --jobs 4 --keep-profiles \
    [--profile ethereum_services_v3_candidate] [--client <label>]
python3 -I $B attribute --elf <ELF> --execution $CACHE/runs/<name>/blocks/24628607/execution.json --out attr.json

# before claiming anything
python3 -I $B run ... --set all                   # 15 blocks, all guards
python3 -I $B check-scope --base origin/codex/rv64-arith-memory --include-worktree
python3 -I autoresearch/guest_efficiency/test_bench.py
```

Any ELF that follows the guest ABI (CONTEXT.md) can be scored; a new client
supplies its own build script under its client directory.

## Scores

- **Primary:** `metrics.scored.instructions_per_gas`. Exact; no timing noise.
- **Co-metric:** `metrics.scored.committed_bits_per_gas`, a frozen proxy
  ([calibration.json](calibration.json)) charging each instruction, Keccak and
  secp call, and candidate service at its estimated prover cost.
- **Levels:** [targets.json](targets.json): L1 8.61, ZisK committed-bits parity
  8.32, L2 ZisK reth parity 6.38, L3 ziskethone parity 2.02, L4 1.50.
- **Promotable:** only results on the admitted profile (`ethereum_services_v2`).
  Candidate-profile results are evidence for a service proposal.

## Guards (all must pass; `run` exits non-zero otherwise)

| Guard | Rule |
|---|---|
| G1 complete basket | every block of the requested set ran |
| G2 exact output | executor completed and the 43-byte output equals the host-validated expected output |
| G3 determinism | the first block, run twice, gives identical counts and output |
| G4 per-block regression | no block more than 2% worse than its frozen baseline |
| G5 holdout generalises | holdout must not regress and must gain at least 50% of the scored gain |
| G6 execution profile | admitted `ethereum_services_v2` or candidate `ethereum_services_v3_candidate` |

## Scope

[scope.json](scope.json), checked by `check-scope`:

- **A guest code:** the current Rust client (`ethereum/rv64/src`, `mem/src`,
  `vendor/`, `Cargo.toml`).
- **B dependencies:** lockfiles and manifests; pinned or vendored only.
- **C new client:** `ethereum/evmone/` or `ethereum/client_*/`.
- **D records:** `ledger/`, `proposals/`, `notes/`.
- **E candidate executor:** `src/frontends/riscv/rv64/ethereum_services/candidate*.zig`
  and `ethereum_execution.zig`, for the execution-only candidate profile only.
- **Locked:** the harness, its data and these documents, linker scripts, target
  spec, `service_abi/`, `build.py`, projection and host validation, all other
  `src/`, `build*`, `vectors/`.

## Rules

1. **Never special-case the basket.** No block numbers, hashes, addresses or
   fixture-derived constants in guest code. The holdout guard catches some of
   this; reviewers reject all of it.
2. **Public output and admitted ABI stay identical.** New services go through
   the candidate profile and a proposal (CONTEXT.md, `proposals/`).
3. **No host hooks or unverified hints.** The guest computes everything it outputs.
4. **Correctness is soundness.** Exact outputs on every block always; a new
   client also needs EEST and differential evidence before adoption.
5. **Licences:** record the licence of any third-party client or library in its
   directory README. Keep third-party sources as a pinned fetch plus patches
   until legal has signed off; do not copy them into the repository.
6. **Record every attempt** in `ledger/attempts.jsonl` (format in
   `ledger/README.md`), including failures and the track it belongs to.

## Promotion (human)

A result becomes the new baseline only after: all guards on `--set all` with
`promotable: true`, `check-scope`, unit tests, a Word16 prefix proof plus fresh
`verify-prefix` with the new ELF, and review. Baseline updates to `basket.json`
and `targets.json` are separate, reviewed commits.
