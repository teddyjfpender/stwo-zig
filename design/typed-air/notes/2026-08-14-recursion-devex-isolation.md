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
- `scripts/typed_air_zig_lane.py` enforces three bounded compiler slots with
  nonblocking `flock` state. V3 assigns a stable Git-private local cache to the
  exact command or an explicit cache group, and protects that cache with its
  own inherited, nonblocking lock. A separate inherited heavy lock serializes
  evidence, proof, benchmark, run, capture, performance, and product-build
  commands even when their keys differ. Ordinary diagnostic gates can still
  occupy the other compiler slots.
- Development-only GREEN reuse is exact: the key binds the tracked, staged,
  unstaged, and untracked checkout closure; argv; toolchain binaries and
  versions; host/kernel identity; full environment identity; stage; timeout
  policy; and all three controller modules. An exact per-key lock prevents
  duplicate gates. The
  controller re-samples that full authority immediately before a cached return
  and after every successful child; source or authority drift returns 74 and
  publishes no GREEN. A forced rerun invalidates the prior GREEN only after all
  execution locks are held, and any RED, TIMEOUT, or DRIFT keeps it invalid.
- Proof/performance/evidence commands and commands naming an unhashed external
  semantic path or bundle never reuse a prior run. They still receive a
  create-only run receipt and retained stdout/stderr. Reusable diagnostics have
  a 20-minute default process-group timeout; `--timeout-seconds` overrides it.
  Timeout sends TERM, continues heartbeats during the grace period, then sends
  KILL and records TIMEOUT. Nonreusable runs remain unbounded unless the caller
  supplies a timeout.
- Zig's default immutable global cache remains shared. A caller-specified
  global cache receives an additional inherited no-wait lock, so distinct
  commands cannot use that nonstandard path concurrently.

## Evidence

The delegated command printed the expected isolated cache:

```text
--cache-dir /tmp/stwo-zig-cache-root-delegation-smoke-2/products/compatibility_tools
```

The following gates passed:

```text
python3 -m unittest scripts.tests.test_delegated_identity_cache
python3 -m unittest scripts.tests.test_typed_air_zig_lane
python3 -m unittest scripts.tests.test_typed_air_zig_gate_cache
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
controller. Related narrow and broad stages should name the same cache group;
the stages have different receipt keys but reuse one exclusively locked local
Zig cache:

```text
python3 scripts/typed_air_zig_lane.py \
  --label <owner>-narrow --stage narrow --cache-group <owner> -- \
  zig build test-<focused> -Doptimize=Debug
python3 scripts/typed_air_zig_lane.py \
  --label <owner>-broad --stage broad --cache-group <owner> -- \
  zig build test-<package> -Doptimize=Debug
```

The first exact GREEN prints its key, run receipt, and retained logs. A later
exact invocation may return that GREEN without launching Zig and prints the
same key and receipt. Use `--force` to rerun it. Mark normative work explicitly
with `--evidence`; target-name classification is an additional fail-closed
guard, not a substitute for that declaration:

```text
python3 scripts/typed_air_zig_lane.py \
  --label <owner>-proof --stage evidence --evidence \
  --timeout-seconds 7200 -- zig build <proof-target>
```

Receipts and logs live under Git's private
`typed-air-zig-gates/{green,runs,logs}` directory. They are development
coordination records, never protocol, performance, or release evidence.

Inspect capacity without starting a compiler with
`python3 scripts/typed_air_zig_lane.py --status`.

Exit 75 means all three slots are occupied; the caller remains source-only and
retries after one reported owner releases. This compiler concurrency does not
authorize concurrent full native/recursive proof transactions: heavy proof
execution stays serialized. Release performance claims still require the
AC-powered, quiet-host, A/A-calibrated procedure in `../PERFORMANCE.md`.
