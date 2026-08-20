# 2026-08-14 — Recursion iteration isolation

## Problem

Parallel recursion work was paying three avoidable iteration costs:

1. A root `--cache-dir` was not inherited by delegated product builds. Every
   lane fell back to the repository-wide `.zig-cache/products/<scope>` and
   contended on the same graph.
2. `xor_codec_roundtrip.zig` loaded postcard by relative path while the focused
   graph also injected `interop_postcard`, so Zig rejected one source file as
   belonging to two modules.
3. Two full recursive proofs were allowed to run concurrently. They were
   semantically independent but oversubscribed the same CPU and made a binary
   proof take about 199 seconds. That number is a contention diagnostic, not a
   prover benchmark.
4. Compiler ownership was coordinated through agent messages. Crossed delivery
   could still start two multi-gigabyte Zig processes before either owner saw
   the other's claim.

## Changes

- `build_support/graph/delegation.zig` now derives the delegated cache as
  `<caller cache root>/products/<scope>`. `STWO_CI_CACHE_DIR` retains its
  existing explicit override semantics.
- `scripts/tests/test_delegated_identity_cache.py` passes a temporary caller
  cache and asserts the exact delegated command path, so this behavior cannot
  silently regress.
- `src/interop/tests/xor_codec_roundtrip.zig` imports the canonical
  `interop_postcard` module.
- `src/integrations/riscv_cpu/build.zig` exposes a focused two-test
  `test-recursive-segment-global-closure` gate. It exercises cross-domain
  cancellation rejection and fail-atomic V2 receipt publication without
  running a proof.
- Expensive proof evidence is serialized during development. Independent
  compilation and allocation-free audits may remain parallel; only one native
  proof transaction owns the host at a time.
- `scripts/typed_air_zig_lane.py` now enforces three bounded compiler slots with
  nonblocking `flock` state and one Git-private local cache per slot. A fourth
  invocation exits 75 and prints all active labels, PIDs, and argv instead of
  waiting or racing. The wrapper replaces any caller-provided local cache on a
  `zig build` command, while the immutable global cache remains shared. It
  launches an argv vector directly, never through a shell, and clears ownership
  under `finally` on every normal command result. Both the slot lock and the
  migration guard are inherited by the command, so an orphaned compiler retains
  ownership even if its wrapper is killed. `--status` reports only live locks,
  ignoring stale metadata. Eight focused unit tests pin wrapped
  command rewriting, live concurrent admission, V1 migration exclusion, status,
  metadata, descriptor inheritance, validation, and cleanup.

## Evidence

The delegated command printed the expected isolated cache:

```text
--cache-dir /tmp/stwo-zig-cache-root-delegation-smoke-2/products/compatibility_tools
```

The following gates passed:

```text
python3 -m unittest scripts.tests.test_delegated_identity_cache
python3 -m unittest scripts.tests.test_typed_air_zig_lane
zig build riscv-opcode-manifest-check \
  --cache-dir /tmp/stwo-zig-cache-root-delegation-smoke-2 \
  --global-cache-dir <zig-global-cache-dir> --verbose
zig build test-recursive-segment-global-closure \
  --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-root-segment-closure-debug \
  --global-cache-dir <zig-global-cache-dir> -Doptimize=Debug
zig build test-recursive-segment-global-closure \
  --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-root-segment-closure-rf \
  --global-cache-dir <zig-global-cache-dir> -Doptimize=ReleaseFast
```

The focused closure runs completed in roughly 1.7 seconds warm Debug and 6.3
seconds cold ReleaseFast on this checkout. Those are DevEx observations only;
they are not protocol-performance evidence.

After serialization, the real binary cohort proof returned to 9.17 seconds
for proving instead of the contended 199-second observation. Its N=1 and N=4
proof bytes were identical, while the observed proving times were 18.04 and
9.33 seconds. The host was on battery, so the ratio remains semantic scaling
evidence and must not enter a publishable performance receipt.

## Operating rule

Every development Zig compile/test command is launched through the bounded
controller; it selects a free slot and injects that slot's local cache:

```text
python3 scripts/typed_air_zig_lane.py --label <short-owner> -- zig build ...
```

Inspect capacity without starting a compiler with
`python3 scripts/typed_air_zig_lane.py --status`.

Exit 75 means all three slots are occupied; the caller remains source-only and
retries after one reported owner releases. This compiler concurrency does not
authorize concurrent full native/recursive proof transactions: heavy proof
execution stays serialized. Release performance claims still require the
AC-powered, quiet-host, A/A-calibrated procedure in `../PERFORMANCE.md`.
