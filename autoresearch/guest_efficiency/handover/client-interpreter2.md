# Handover: client interpreter pass 2 (paused 2026-11-01)

Branch `codex/rv64-guest-client-interpreter2` (from `origin/codex/rv64-guest-efficiency`;
merge at start was a no-op, already up to date at `765f178da`). Paused on coordinator
instruction mid-task; no change to the scored client is kept yet.

## Done and verified

- **Baseline (admitted, `--set all`, adapter on, all guards pass):** scored 6.801, holdout
  5.611, all 6.566 instr/gas. Interpreter bucket 1.535/gas; `dispatch_cgoto` 1.117/gas =
  28.1 instr per dispatched op (17.71M dispatched ops); JUMPDEST analysis 0.265/gas.
- **Reuse measurements (instrumented host build, all 15 blocks):** 17.9M dispatched ops,
  4.0M unique (code, pc) ops (reuse 4.5x), 2.1M segment entries, 0.42M unique segments.
  61% of unique ops (2.47M) sit in segments entered exactly once. Per-contract tiering
  (translate only code seen in >= F frames) barely helps: F=2 covers 80% of dispatches but
  still translates 3.17M of the 4.3M unique ops.
- **Lazy translated-segment dispatch (patch 0023), measured, NOT kept.**
  Segments (JUMPDEST/pc 0/JUMPI fall-through/split to next JUMP/JUMPI/terminator/JUMPDEST)
  translated on first entry into 8-byte records (handler address + immediates); one entry
  check (segment base gas, stack need, growth <= 32) replaces per-op checks; gas-reading
  ops get exact-gas correction; any shortfall hands the frame to `dispatch_cgoto` at the
  exact pc/stack/gas; fused static jumps resolved once and patched.
  - Exact on all 15 blocks (host and guest), all guards pass.
  - `dispatch_xlat` 0.836/gas vs `dispatch_cgoto` 1.117/gas (-0.28/gas; handlers near
    minimal: POP 4, PUSH1 9, DUP2 12, SWAP1 19, segment entry 12 instructions).
  - But translation costs more than it saves: v1 translator all 7.203 (+0.64/gas;
    `xtranslate` 0.81/gas, ~890 instr per segment); v2 table-driven translator all 6.834
    (+0.27/gas; `xtranslate` 0.47 + `xinsert` 0.07/gas, ~27 instr/op + ~250/segment).
  - Ceiling: savings are ~31 instr per unique op (0.28/gas over 4.5x reuse); even an ideal
    translator (~20/op incl. segment overhead) only breaks even. Recording-on-first-execution
    or segment tiering estimated at most ~+0.1/gas with high complexity.
  - Patch parked at `autoresearch/guest_efficiency/notes/attempts/0023-evmone-rv64-translated-segments.patch`
    (not applied by build.py). On the PR branch it is parked unapplied in
    `client_evmone/patches/wip/` because the number 0023 collides with the v3 modexp patch;
    renumber if it is ever landed.
- **Differential fuzzer** `client_evmone/tests/xlat_difffuzz.cpp` (extends ziskethone's
  fused-dispatch fuzzer): xlat vs fused cgoto vs plain switch; compares status, gas_left,
  gas_refund, output, storage/transient/logs/calls; reuses one analysis over 4 gas limits
  and random revisions. Against 0023: 300k programs / 1.2M runs, 0 mismatches (v1);
  100k / 400k, 0 mismatches (v2). Mutation check: entry-gas off (hangs = detected),
  rem-correction off, underflow check off, overflow check off, LT swapped, late hand-over
  off: all detected within 20k programs.

## In progress / exact state

- `build.py` `run_tests` now builds and runs `xlat_difffuzz` (20k programs). **Known issue:**
  with 0023 not applied, `set_option("xlat","no")` fails and the fuzzer exits 2, so
  `build.py --host --tests` will fail. Fix before relying on it: make the fuzzer skip the
  xlat VM (compare fused vs plain only) when the option is absent, or drop the hook.
- Candidate-profile baseline (`--profile candidate`, mem,sha,arith) **FAILED G2 exact
  output** on this branch with no interpreter change (G6 passes). Not investigated;
  possibly the candidate executor/harness on this branch, or the EEST-fixes merge state.
  Check `runs-base-candidate.log` in scratch before any candidate claim.
- No ledger line written yet for the 0023 attempts (data: scratch `runs/x1-admitted`,
  `runs/x2-admitted`; ELF sha256 c61ec61a... and 6cbaeafc...).

## Next steps (in order of expected value)

1. Fix the fuzzer/no-xlat issue above; write ledger lines (0023 v1, v2: not kept) and add
   the negative result to `notes/client-interpreter.md`.
2. Cheap cgoto changes (zero preprocessing), each with the fuzzer (fused vs plain) and
   mutants:
   - PUSH1..8 writes a zero then the value into limb 0: construct the word directly
     (~-1 instr per PUSH1..8, ~0.01/gas).
   - Deferred gas branch for pure const-gas ops (PLAIN/PLAIN_S impls): keep `gas -= c`, drop
     the branch; keep checks on all Result/TermResult ops, JUMP/JUMPI/JUMPDEST; add explicit
     `gas < 0 -> OOG` on 0-cost terminators (STOP/RETURN/REVERT/INVALID) and make stack-error
     and undefined-op exits report OOG when gas < 0 (~0.03/gas). Consensus-sensitive.
3. Larger structural ideas judged not worth it on this basket: TOS register caching
   (~0.07/gas est., touches every handler), per-contract tiering, recording translator.
   The ~1.0/gas interpreter target is not reachable on RV64IM without amortizable
   preprocessing; Zbb (`rev8`, `sh3add`) remains the big lever (see zbb-gap-report).

## How to resume

Scratch: `/private/tmp/claude-501/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/scratchpad/client-interpreter2/`
- `tools/br.sh NAME admitted|candidate` build ELF + run `--set all` (executor `exec/`,
  built with `bench.py build-exec --out exec`; host adapter binary `host/`).
- `tools/fz.sh HOSTDIR OUT` build the fuzzer against a host build's objects.
- `tools/mutant.sh NAME OLD NEW` mutate staged `baseline_xlat.inl`, rebuild host, fuzz.
- `tools/mkpatch.sh` regenerate 0023 from `dev/a` (pristine) vs `dev/b` (edited).
- `tools/buckets.py`, `opcodes.py`, `topfn.py`, `pcdis.py` for attribution.
- Probe build (`probe/`): instrumented `dispatch_cgoto` for reuse statistics.
