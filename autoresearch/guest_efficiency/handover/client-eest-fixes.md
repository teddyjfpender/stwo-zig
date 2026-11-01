# Handover: evmone client EEST fixes (paused 2026-11-01)

Branch `codex/rv64-guest-client-eest-fixes` (from `origin/codex/rv64-guest-prover-eest`).
Commits: `a3989263a` (bug 1, verified), `365f1b165` (WIP checkpoint by the
coordinator: bug 2 code + upstream write-up), then this handover.

Scratch (not in git): `SCR=/private/tmp/claude-501/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/scratchpad`
- `$SCR/client-eest-fixes/cache/` — EEST cache: symlinks to the old cache
  (fixtures, stateless, target, target-rust-host, rust-elf, exec) plus a new
  `evmone/` holding EEST builds **with both fixes** (host sha `004c96f4…`,
  ELF sha `8da51c1d…`).
- `$SCR/client-eest-fixes/prod/` — production (non-EEST) host + admitted ELF with both fixes.
- `$SCR/client-eest-fixes/work-bls/` — guest re-run of the eip2537 group (bug-1 build only).
- `$SCR/client-eest-fixes/{hostcheck,guestcheck}.py` — re-run only the old
  receipt's evmone failures with a given binary/ELF.
- Old full run (inputs, gen, results, receipt): `$SCR/eest/work/full`.

## Bug status

### 1. BLS G2 crash on RV64 — FIXED + VERIFIED (commit a3989263a)
Root cause: patch 0002 makes portable-C blst use 64-bit limbs; `quot_rem_64`
calls `quot_rem_n(.., n = NLIMBS(64) = 1)` whose `__builtin_assume(n%2 == 0)`
is then UB and miscompiles (stack corruption -> garbage memcpy pointer). Hit by
G2 GLS multiplication (`div_by_z`), i.e. G2MUL and single-point G2MSM. Upstream
blst master still has the assume (unreachable there: no 64-bit-limb no_asm).
Fix: patch 0002 weakens it to `n != 0`. Reproduced natively (aarch64,
`-D__BLST_NO_ASM__` traps at that line). Host test `tests/blst_portable.c`
(run by `build.py --host --tests`): portable vs assembly, 114 results identical.
EEST eip2537 guest re-run (3,994 inputs incl. controls): evmone 1,993 PASS,
0 FAIL, 4 ERROR (was 40 FAIL); rust 1,997 PASS.
Note: on the PR branch the duplicate blst patch 0022 was removed because this
0002 change carries the same quot_rem_64 fix.

### 2. Table sizing from the gas limit — FIXED, PARTLY VERIFIED (commit 365f1b165)
Root cause: `glue/stwo_client.cpp` reserved `gas_limit/2400` account and
`gas_limit/1900` slot rows (bad_alloc at 2^52..2^63 on host; guest heap
exhausted from 500M). Fix: `row_reserve(gas_used, per_row_gas)` =
`min(gas_used, 60M) * 5/4 / per_row_gas + 1024`; past it tables grow on demand
(vectors push_back, hash index rehashes; records are separate allocations,
rows are addressed by index — audited: `set_storage` holds `tx_original_at`
ref but no load in between; StateRoot leaf pointers unused under ZEG_STWO;
`bal_id_at` is Amsterdam-only).
Evidence: all 200 old host-tier evmone failures now PASS (`hostcheck.py`);
309 old guest-tier non-BLS evmone failures: 307 PASS, 1 FAIL
(`stStaticCall/static_call1_mb1024_calldepth` block 1: EVM memory of ~1024
frames x 1 MB; host peak RSS 595 MB > 212 MiB heap; Rust guest fails it too —
genuine resource limit), 1 ERROR (`call50000_sha256`, 10^10 step limit, Rust too).
Basket (15 blocks, admitted, with the client's input adapter, production
builds; base = `$SCR/eest/evmone-prod` sha `715ae8b3…`): all guards G1-G6 pass,
exact outputs; instructions 3,585,744,924 -> 3,585,175,445 (-569,479, -0.016%);
scored instr/gas 8.322446 -> 8.321204, all 8.050633 -> 8.049355.
Results: `$SCR/client-eest-fixes/basket-{base,new}/result.json`.
(The 8.500 figure in the old README was measured without the adapter.)
Not yet done: full host-tier pass and group re-runs through `eest.py`, receipt.

### 3. Max-depth EIP-7702 call chain OOM — FIXED by bug 2 (verified on targeted re-run)
Root cause was not per-frame growth: the fixture's gas limit is 1e14, so the
bug-2 reserve was ~4e10 rows (host RSS climbed to 38 GB while zeroing hash
buckets). With the bug-2 fix it passes on host and guest (19.3M instructions).

### 4. Gas-heavy BLS MSM blocks over 10^10 — NOT STARTED (beyond confirming still 4 ERROR)
`valid_gas_g1msm`, `valid_gas_g2msm`, `valid_multi_inf`, `invalid_multi_inf`.
Next: run each with a higher `max_steps` (e.g. 5e10, custom cfg as in
`eest.guest_run`) to report instructions and instr/gas; profile with
`bench.py attribute` if a clear hotspot appears.

## Next steps (in order)
1. Update `failure-classification.json` (BLS + sizing + 7702 groups -> fixed;
   keep static_call1_mb1024_calldepth / call50000_sha256 as resource limits),
   README Known gaps, client_evmone README ("Lazy rows", "Still open").
2. Full host-tier pass + guest re-run of affected groups with the new cache,
   new receipt `vectors/reports/rv64-ethereum-20261101/eest-guests-v2.json`.
3. Bug 4 cost measurement.
4. Commit/push each step.

## Resume commands
```sh
SCR=...; F=$SCR/client-eest-fixes; E=autoresearch/guest_efficiency/eest/eest.py
# new work dir sharing old inputs/gen; copy old guest results, then delete the
# affected fixture files' results so guest re-runs only those
mkdir -p $F/work && ln -sfn $SCR/eest/work/full/gen $F/work/gen && ln -sfn $SCR/eest/work/full/inputs $F/work/inputs
cp -R $SCR/eest/work/full/guest $F/work/guest   # then rm affected <fid>.json
python3 -I $E host  --cache $F/cache --work $F/work --jobs 4
python3 -I $E guest --cache $F/cache --work $F/work --jobs 4
python3 -I $E receipt --cache $F/cache --work $F/work \
  --out vectors/reports/rv64-ethereum-20261101/eest-guests-v2.json
```
Rebuild (if sources change): `build.py --out $F/cache/evmone --cache
$SCR/client-evmone/build/cache --eest [--host --tests]`.

## Known issues / risks
- Growth-on-demand audit is by reading, not by a test that forces growth past
  the reserve on the guest (only indirectly: EEST blocks with tiny gas_used).
- `row_reserve` trusts payload gas_used only as a size hint (capped at 60M).
- `upstream-reth-issues.md` (two reth/alloy-evm bugs) is written, not filed;
  code references verified at alloy-evm 065a125c and main (2026-11-01).
