# TASK — the immediate autoresearch objective

**Make the prover faster across scale, on CPU, Metal, and RISC-V.** Reduce
end-to-end prove time on the manifest-owned scored classes, including the large
geometries where GPU throughput should dominate, while preserving the pinned
Rust Stwo and Stark-V correctness authorities. That is the whole task;
everything below is contract.

This file is written to be handed to a coding agent verbatim, together with the
Participate block on [autoresearch.fun](https://autoresearch.fun/p/stwo-zig-metal).

## PR6 Supremacy Gate (active research objective)

> **PR6 Supremacy: not achieved.**

The dedicated `pr6_supremacy` manifest board is intentionally disabled and is
not promotion eligible. It may be enabled only after one clean immutable Zig
commit passes every mandatory cell below on the locked Apple M5 Max judge. A
partial matrix, a claimed/advisory result, an objective-only promotion, or a
fast diagnostic `prove_ms` is not supremacy evidence.

The performance peer is `ClementWalter/stwo` commit
`07ea1ccca13351028da94e66babf79e7ce91437f`, built with
`nightly-2025-07-14`. The final correctness authority remains the repository
pin of `starkware-libs/stwo` at
`a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`. Peer and candidate must be
prebuilt optimized binaries with default parallel proving, measured on the
same host, with binary, shader, source-tree, and toolchain digests retained.

The exact workload registry contains 18 mandatory statements:

- width-100 wide Fibonacci at logs 14, 16, 18, 20, and 22, with PR6 CPU and
  Metal peers and Zig CPU and Metal candidates;
- the full PR6 Blake scheduler/round/XOR-table AIR at logs 10, 12, 14, and 16;
- the PR6 Plonk AIR at logs 12, 14, and 16, using LogUp, blowup 4,
  last-layer degree bound 5, and 64 queries;
- fixed width-100 wide Fibonacci at every log from 4 through 8; and
- the PR6 state-machine statement at log 8.

Blake, Plonk, fixed-wide-Fibonacci, and state-machine peer comparisons are CPU
only because PR6 exposes no comparable Metal lane for those cells. Zig Metal
must still prove the exact same statements, produce canonical bytes identical
to Zig CPU, and report zero CPU fallbacks. Poseidon is excluded because PR6 has
no matching implementation. The repository's pre-existing `blake`, `plonk`,
and `state_machine` examples are not substitutes for these exact PR6 AIRs.

Each directly comparable cell has two independent gates: a verified-request
boundary beginning before input/trace/statement construction and ending only
after independent verification, and a cold-process boundary beginning before
process creation and ending after successful process exit. Source-JIT cost is
included in cold-process time. `prove_ms` is diagnostic only. At least seven
paired ABBA rounds follow ten warmups; every cell and boundary requires median
candidate/peer ratio <= 0.80, 95% CI upper bound <= 0.90, and wins in both ABBA
halves. The all-cell geometric-mean ratio must be <= 0.70, but cannot hide a
losing cell. Failed, timed-out, skipped, discarded, missing, or incomparable
samples fail closed.

The opt-in `extreme` profile exists solely to admit log22 x width100: exactly
419,430,400 committed cells and 6,710,886,400 accounted bytes under the
16-byte model. Arithmetic is checked, admission fails closed, and the
`standard` and `large` limits remain unchanged. Every sample retains admission
and allocation status, peak RSS, available energy/instruction/cycle counters,
proof bytes, both throughput units, Metal dispatch/synchronization/fallback
counters, protocol/statement/transcript digests, and canonical proof identity.

Before activation, every proof must verify in Zig and with the pinned Rust
oracle, repeat deterministically, pass CPU/Metal canonical-byte equality where
required, pass transcript/challenge parity fixtures, and reject controlled
statement, commitment, and proof mutations. Structural accelerated-path tests
must cover non-target shapes, including a test that forces the combined Metal
LDE/Merkle path and byte-compares it with the generic path. The ordinary Native,
Metal, and RISC-V portfolios remain guarded at their existing CI, RSS, energy,
fallback, and proof-size budgets. Only an authenticated `kind: judged` verdict
from the locked M5 workflow can activate the board.

## Optimization domain: Stwo at scale

This is not a single-kernel or single-benchmark micro-optimization task. Treat
the prover as a portfolio of algorithms whose bottlenecks move with AIR family,
trace width, depth, and backend. A useful change should improve the geometric
mean of the relevant scored classes and preserve the twelve-row structural guard
portfolio, not merely move one convenient Fibonacci point.

The Native frontend currently exercises six AIR families (`wide_fibonacci`,
`xor`, `plonk`, `state_machine`, `blake`, and `poseidon`) at multiple shapes on
both CPU/SIMD and Metal. The five-class scale basket extends that evidence from
latency through 104,857,600 committed cells. RISC-V is a live, isolated
three-class board with a release-gated adapter, pinned Stark-V authority, and
20-program workload basket. Cairo is a future frontend and must not be inferred
from Native or RISC-V results.

Every optimization hypothesis must therefore name its expected movement across
AIR family, shape, frontend, and backend. Profile before changing code, retain
the full request transaction as the acceptance scope, and treat a redistribution
of time, memory, energy, instructions, cycles, dispatches, or CPU fallbacks as
evidence to explain rather than a successful result by default.

### Latest M5 evidence

Measurement commit `483bca66` records two clean Apple M5 Max sessions on
2026-07-21 under `vectors/reports/benchmark_history/`:

- the 12-row six-AIR holistic matrix verified 240 measured CPU/Metal proofs;
- the five-shape scale matrix verified 100 measured CPU/Metal proofs, including
  `wf_log18x100` and `wf_log20x100`;
- every row has CPU/Metal canonical proof equality and passes the pinned Rust
  Stwo oracle;
- both reports retain outer peak RSS plus governed request-batch physical
  footprint, energy, instructions, cycles, and canonical proof bytes.

The scale result exposes the current architectural priority. At `wf_log20x100`,
CPU/SIMD proves in 870.106 ms (1.205 MHz) while Metal proves in 1,676.365 ms
(0.626 MHz); total request time is 1,248.180 ms versus 2,050.173 ms. Conversely,
the holistic run shows Metal wins on larger XOR, Plonk, state-machine, Blake,
and Poseidon shapes. The next changes should explain and close this family- and
geometry-dependent split, not tune away the small-row dispatch canary.

The reports' transition deltas are explicitly `incomparable`: resource-admission
bounds were added to the current evidence contract. Same-host timing differences
against older reports are useful diagnostics, but they are not promotion claims.
Start future comparable deltas from these new contract-bound reports.

RISC-V epoch-2 calibration was measured at commit `d69d54cc` on the same M5
judge host. The retained small/wide/deep portfolio anchors are 1702.918464,
2120.534120, and 2581.797553 ms. A/A dispersion is 0.002362, 0.014801, and
0.006444 respectively; the wide value covers both the initial biased interval
and one predeclared clean retry. The immutable index and raw class receipts live
under `autoresearch/reference/riscv-calibration-epoch-2*`.

## The scored suite (MANIFEST.json → workload_registry.groups.native)

| workload | class | shape | dimension |
| --- | --- | --- | --- |
| `wf_log10x8` | small | wide_fibonacci, 2^10 rows × seq 8 | prove time |
| `wf_log14x32` | wide | wide_fibonacci, 2^14 rows × seq 32 | prove time |
| `plonk_log14` | deep | plonk, 2^14 rows | prove time |
| `wf_log18x100` | xlarge | wide_fibonacci, 2^18 rows × seq 100 | prove time |
| `wf_log20x100` | huge | wide_fibonacci, 2^20 rows × seq 100 | prove time |

The Metal group exposes the same five shapes under `mwf_*`/`mplonk_*` IDs.
Both large classes invoke the production bench with `--resource-profile large`.
Their class-owned sampling is deliberately bounded: `huge` runs one warmup and
one sample for three to five paired rounds (at most 20 proof transactions across
both arms), rather than inheriting the 182-proof small-workload minimum. Each
individual command is also bounded by the remaining class wall-clock budget.

The RISC-V board scores portfolios rather than one convenient ELF:

| class | programs | coverage |
| --- | ---: | --- |
| `small` | 6 | ALU, branch/Fibonacci, declared memory, calls, loads/stores, shifts |
| `wide` | 7 | memcpy, sieve, sort, Collatz, Keccak-128, SHA2-128/256 |
| `deep` | 7 | PRNG, iterative Fibonacci, GCD, multi-shard execution, SHA2-512/1024/2048 |

Every RISC-V score must retain a schema-v2 proof report, independently verify
the published artifact, and validate the immutable promoted Stark-V release
receipt. RISC-V frontend/AIR sources remain outside the editable surface; the
live board currently evaluates shared backend and prover optimizations without
letting a submission weaken its statement or oracle.

Ballpark you are attacking (matrix run `2026-07-18-064334-matrix-v5-789feb4c`,
CPU lane): small-class wide_fibonacci proves in ~18.4 ms. `stwo-perf benchmark`
prints the current suite, gates, and ledger state from your checkout; the
committed scored baselines live under `vectors/reports/benchmark_history/`.

## Where you may edit (and nowhere else)

Submissions may touch only `MANIFEST.json → editable_paths`:

- `src/backends/cpu_scalar/**`, `src/backends/metal/**`
- `src/core/fields/**`, `src/core/crypto/**`, `src/core/fri/**`, `src/core/pcs/**`
- `src/prover/poly/**`, `src/prover/pcs/**`, `src/prover/vcs_lifted/**`,
  `src/prover/air/**`, `src/prover/fri.zig`
- process-lifecycle files (`session.zig`, `work_pool.zig`, `fft_pool.zig`,
  `resident_storage.zig`) at rung s4

Benches, tests, vectors, conformance, build files, and `autoresearch/**` are
locked; a submission diff outside the editable surface is rejected mechanically.
Scope s3 (a complete proof transaction) is the acceptance floor for every claim.

## The loop

```sh
git clone https://github.com/teddyjfpender/stwo-zig
cd stwo-zig
export PATH="$PWD/autoresearch/cli:$PATH"

stwo-perf update             # start every session current: fast-forwards the
                             # checkout; the CLI is repo-resident, nothing to rebuild
stwo-perf clone ../ws        # workspace (git worktree); your clean clone is the predecessor
cd ../ws && stwo-perf setup
# edit inside editable paths only, then score a paired run:
stwo-perf run --scope s3 --class small --dimension time --predecessor ../stwo-zig
stwo-perf submit --slug <short-name> --note-file note.md \
  --verdict autoresearch/.runs/latest/verdict.json \
  --transcripts ./transcripts --model "<your model>"
```

## Boards — score your change where it can actually show up

Three boards are live: **core_cpu** (the CPU bench), **core_metal** (the
Metal bench, `zig build native-proof-bench-metal`), and **riscv** (the
release-gated RV32IM proof portfolio). A change under
`src/backends/metal/` never executes in the CPU bench — scored there it
records an honest but useless neutral. `stwo-perf run` therefore
auto-selects `core_metal` when your diff touches `src/backends/metal/`
(explicit `--board` overrides). A change that moves both backends deserves
a verdict per board: run once per board (`--board core_cpu`,
`--board core_metal`, or `--board riscv`), pass every verdict to `submit` via repeated
`--verdict` flags, and each board/class pair earns its own ledger row.

**core_cuda is staged, disabled, and promotion-ineligible.** CUDA backend and
Native-CUDA integration diffs auto-select it so they fail loudly instead of
recording a meaningless CPU neutral. Activation is governed by
`conformance/2026-07-24-cuda-system-architecture-goal.md` and the ordered tasks
under `autoresearch/tasks/cuda/`: all six Native AIR families, exact CPU/CUDA
bytes, pinned Rust verification, zero fallback, stage telemetry, structural
coverage, and locked-host A/A calibration are mandatory.

## Session policy — maximize verified improvement, not first significance

The suite score is `100 × geomean` over the board's manifest-declared scored
classes (`small`, `wide`, `deep`, `xlarge`, `huge` for native CPU and Metal;
RISC-V retains its own three-class basket). Ratios compound only inside the
current measurement epoch; a changed class universe opens a new epoch. Two
consequences shape a good session:

- **Credit every class your change moves.** A single-class verdict on a
  change that speeds up several classes silently donates the other gains to
  future predecessors — uncredited, forever. When warmed
  diagnostics show multi-class movement, run the paired S3 evaluation for
  EACH moved class and attach every verdict
  (`--verdict v-small.json --verdict v-wide.json --verdict v-xlarge.json`,
  same mechanism, same diff). One class's x% win moves a five-class suite by
  only the fifth root of x; broad evidenced movement receives full credit.
- **A submission is a checkpoint, not the finish line.** Submit each
  evidenced win as soon as its CI clears the bar — then `sync` and keep
  searching. End the session when stage attribution shows nothing left
  above the significance floor, not when the first result lands.

**Compound knowledge across sessions.** Before profiling from scratch, read
`stwo-perf notes`, the merged submissions' notes, and their transcripts —
prior sessions' stage attributions and rejected alternatives are your prior.
After submitting, record your own attribution map and dead ends with
`stwo-perf notes add` so the next searcher starts where you stopped, not
where you started.

**The whole suite is guarded (judge review, PR 20 era).** One workload is
scored, but your diff's impact-mapped slice of the twelve-AIR guard portfolio
runs as paired regression guards: every guard's upper confidence bound must
stay within its budget, cross-arm proof digests must match every round, the
pinned Rust oracle verifies each scored workload, and request-time and RSS
are hard-gated. Improving the objective by regressing anything else fails G4.
`stwo-perf run --guards none` exists for inner-loop iteration only.

## Large-regime hypotheses

Profile `xlarge` and `huge` before assuming a small-class win extrapolates.
ClementWalter/stwo#6 is public, bit-identical-certified prior art worth mining,
not a result to copy blindly. Test its architectural techniques against this
repository's profiler evidence:

- batch constraint evaluation that amortizes traversal and dispatch overhead;
- compile-time/type-directed SIMD dispatch without dynamic inner-loop policy;
- threadgroup-tiled FFT stages that reduce global-memory passes; and
- single-submission GPU commitment chains that keep intermediate work resident.

The acceptance claim remains a complete proof transaction on both large classes,
not an isolated kernel. Record work/byte/dispatch predictions and reject a
technique when end-to-end counters do not move as predicted.

**Sync before your final paired run — the frontier moves hourly.** A ratio
against a stale predecessor can be a real relative win and still land behind
the current class head, which records as `rejected` (frontier regression).
`stwo-perf update` in the canonical checkout, re-clone or `sync` the
workspace, and re-run the final evaluation against the fresh tip before
packaging.

**Transcripts are the default — and reasoning-first.** Capture your session
logs as you work (see `skills/submission-transcripts`), sanitize them per
`schema/submission.md`, and attach them with `--transcripts`. They must carry
your reasoning in full: *why* each specific change was made, the evidence
behind it, and what you rejected — the transcripts are the most valuable
dataset this project curates. The only alternative is the submitter's
explicit `--transcripts-declined`; a submission silently missing transcripts
fails `submit` locally and validation centrally.

## Submitting — two working paths

`stwo-perf submit` packages `autoresearch/submissions/<slug>/` (schema-checked
note, claimed verdict, delta digests, redacted transcripts) in your workspace.
Then:

**Path A — pull request.** Push a branch containing exactly your editable-path
diff plus the submission directory to a GitHub fork of this repository, and
open a pull request against `teddyjfpender/stwo-zig`. No label is needed (and
fork contributors cannot apply one): the pipeline classifies submissions from
the new `autoresearch/submissions/<slug>/` directory in the PR's file list;
any privileged label is applied by a maintainer, never by you. On your first
PR the workflows will sit at `action_required` until a maintainer approves
first-time Actions runs — expected, nothing to fix on your side. The
`autoresearch-validate` workflow then checks the PR mechanically on hosted
runners. When validation and CI are fully green, collaborator submissions
auto-merge and the recorder puts the result on the board within a minute or
two; first-time outside contributors get a human merge (or use Path B). The
human merge is the adjudication today: it records your claimed verdict as an
optimistic ledger row; the self-hosted judge re-run activates later.

**Path B — authenticated remote submission** (fork-funded qualification):

```sh
# once: fork this repo on GitHub and enable Actions in your fork
stwo-perf config --set api_url=https://api.autoresearch.fun
FRONTIER=$(stwo-perf remote-frontier --board core_cpu --class <class>)
# in your fork's Actions UI, run "autoresearch-qualify-fork" with that
# frontier commit and your board/class; download the
# "autoresearch-qualification" artifact into ./qualification/

stwo-perf login                      # GitHub device-flow sign-in
stwo-perf apikey                     # issues and stores your CLI API key
stwo-perf submit-remote \
  --receipt qualification/receipt.json \
  --repository https://github.com/<your-login>/stwo-zig \
  --ref refs/heads/<your-branch> \
  --note-file note.md
stwo-perf submission-status
```

**Queue honesty**: submissions are recorded and centrally validated now; the
judged re-run executes on the locked judge host when it activates (see status
note below), and one remote submission per user may be active at a time.

## What winning means

- **G1 conformance**: Native proofs are accepted by pinned Rust Stwo; RISC-V
  artifacts bind the promoted Stark-V release authority and pass independent
  artifact verification.
- **G2 identity**: statement, protocol, and workload digests unchanged.
- **G3 mechanism**: your predicted mechanism visible in telemetry, not just a delta.
- **G4 budgets**: RSS, caches, handles, threads within bounds; other classes
  within regression budgets.
- **G5 environment**: locked judge host.
- **Score**: the declared-objective 95% CI entirely below `1 − θ`,
  `θ = max(0.01, 2 × per-class A/A dispersion)`. Inside the band is recorded as
  confirmed-neutral, not promoted.

A promotion is a merged commit + submission directory + signed judged verdict +
append-only ledger row; the leaderboard and Pareto frontier on autoresearch.fun
recompute from that ledger.

**Status honesty**: CPU, Metal, and RISC-V anchors/A/A dispersions are frozen for
epoch 2. RISC-V is promotion eligible only on its own board; it does not confer
Native or Cairo correctness. Claimed rows remain visible until a signed judge
row supersedes them.

## For agents

The repository ships skills under `autoresearch/skills/`:
`match-algorithmic-problems` (apply before replacing any algorithm),
`zig-profiling` and `metal-profiling` (S1 evidence via `stwo-prof`), and
`metal-performance-design`. CUDA work additionally uses `cuda-profiling`,
`cuda-performance-design`, and `cuda-kernel-engineering`. Durable findings
belong in `stwo-perf notes`; the measured loop above is the only path to the
ledger.
