---
name: zig-profiling
description: Isolate Zig code into a scratch harness and profile it with in-process hardware counters (instructions, cycles, IPC, energy), stack sampling, codegen summaries, and ABBA A/B comparison via the stwo_perf statistics. Use for any CPU performance question — finding inefficiency and redundancy, verifying vectorization claims, attributing cost to compute vs memory vs dependency chains vs overhead — before touching prover code.
---

# Zig profiling

The tool is `tools/perf/stwo-prof` (`zig` lane). It exists so every CPU
performance claim is measured, attributed, and compared — never vibed. The
reward loop is data-driven design: counters decide, opinions don't.

## The loop

```bash
stwo-prof zig isolate <name> [--from file.zig] \
    [--import stwo=$REPO/src/stwo.zig]           # scratch dir outside the repo
# edit ~/.cache/stwo-prof/<name>/workload.zig     (contract in the header)
stwo-prof zig run <name> --iters N               # counters: ns/op, instr/op,
                                                 # cycles/op, IPC, energy, RSS
stwo-prof zig asm <name>                         # codegen: instrs, NEON share
stwo-prof zig sample <name>                      # inclusive hot-frame table
stwo-prof zig compare <a> <b>                    # ABBA A/B with bootstrap CI
```

Every subcommand takes `--json` and writes its structured result into the
scratch dir (`counters.json`, `asm.json`, `sample.json`,
`compare-vs-<b>.json`) — read those instead of re-parsing terminal output.

## Profile live repo code, not copies

`--import name=path` wires a repo module into the harness build, so the
workload can do:

```zig
const stwo = @import("stwo");
const M31 = stwo.core.fields.m31.M31;
```

This is the default depth move for any question about existing prover code.
Never copy repo code into a workload: copies drift the moment the codebase
evolves, and a stale copy measures software that no longer exists. With a
wired import the harness compiles the live source on every run — a compile
error is the tool telling you the API moved, and `run --json` records the
wired paths as provenance. Isolate two harnesses against the same import to
A/B a current code path against a candidate rewrite (e.g. scalar `inv()` vs
`batchInverseInPlace`) with both arms reading identical field arithmetic.

Counters come from `proc_pid_rusage` deltas taken in-process around the
measured loop — no profiler attach, no sudo, near-zero dispersion. That is
why instructions/op and cycles/op are the primary observables and wall time
is secondary (the harness scope-ladder rule for S0/S1).

## Reading the numbers (the four walls)

- **IPC high (>3) and ns/op flat as you widen** → compute-bound: only fewer
  instructions help; check `asm` for NEON share and instruction count.
- **IPC low (<1) with a serial algorithm** → dependency-chain-bound: widen
  into independent lanes (batch inversion, four-lane hashing); more SIMD
  will not help until the chain is broken.
- **IPC low with heavy `mem` counts in `asm`** → memory-bound: measure
  against the host STREAM ceiling; only fewer passes or better locality help.
- **ns/op >> cycles/op × cycle time** → overhead (page faults, allocator,
  fan-out): profile the harness setup, not the kernel.

## Traps this harness defends against — verify anyway

- **Constant folding**: a pure function of constants is evaluated at compile
  time; LLVM also closed-forms reducible loops (a sum-of-squares loop costs
  O(1)). The `run(seed)` contract threads a runtime value through every
  call. The tell is instructions/op near zero — check it every time.
- **Dead-code elimination**: return a u64 derived from the work; the harness
  accumulates it through `std.mem.doNotOptimizeAway`.
- **Call overhead**: keep one unit ≥ ~1µs or batch internally and set
  `ops_per_call` so per-op numbers stay honest.
- **Inlining in `asm` output**: the workload usually inlines into `_main`.
  Mark it `pub noinline fn run(...)` when you need a separate symbol to
  inspect; remove `noinline` before timing (inlining is part of the result).
  `asm` hides std/runtime symbols (the harness's own I/O plumbing) by
  default — `--all` shows them, and `--symbol <substr>` narrows to one.
- **Noise**: `compare` interleaves ABBA and reports a bootstrap CI on wall
  ratios; instruction ratios are near-deterministic — when wall moves but
  instructions don't, suspect the machine, not the code.

## Rules of engagement

- A vectorization claim requires `asm` evidence (NEON share on the hot
  symbol), not source-level belief — the CONTRIBUTING SIMD rule, mechanized.
- An A/B verdict requires the CI to exclude 1.0; `compare` prints the
  verdict explicitly — "no verdict (CI spans 1.0)" means collect more
  rounds or accept neutrality, never round in your favour. Promotion-grade claims still go through the repository's paired
  end-to-end benchmark gates — this harness is the inner loop that generates
  hypotheses cheaply.
- Findings worth keeping go into the PR or design note with the
  counter numbers inline; scratch dirs are disposable, evidence is not.

## Confirm hypotheses in the large scored regime

The native CPU board scores `xlarge` (`wide_fibonacci` log18 × 100 columns) and
`huge` (log20 × 100) in addition to small/wide/deep. Use S1 isolation to choose
an implementation, then run the relevant complete-proof class. Do not infer
large-shape behavior from a small proof: cache capacity, memory traffic, pool
occupancy, FFT traversal, and constraint batching change regime.

For scale-oriented searches, explicitly test the public techniques demonstrated
in ClementWalter/stwo#6: batched constraint evaluation and type-directed SIMD
dispatch. In Zig, prefer comptime-selected concrete paths over runtime type or
feature policy in the hot loop. Preserve the Rust Stwo oracle as the final
correctness authority and require the current epoch's large-class gates before
claiming suite credit.
