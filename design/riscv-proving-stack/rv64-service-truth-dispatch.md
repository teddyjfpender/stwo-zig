# Rejected truth-first service dispatch experiment

The isolated `codex/rv64-truth-dispatch-qualified` branch recovers the scheduling idea from `92f244fec` onto LS7
`fe3b29fc0`, without replacing the scheduler or owned CPU/truth worker. It is
producer-only, explicitly enabled with `--truths-first`, and **off by default**.
No AIR, proof suite, public statement, transcript or geometry changes.

The integration branch retains this report and its receipts only. It does not
include the experimental `--truths-first` runtime option or dispatch source.
The measurements below reject adopting that experiment.

The producer builds one permutation: truth workers sorted by declared MAIN plus
INTERACTION cells descending, ties by their original ordinal, followed by CPU
workers in original order. This is a static cost proxy, not a measured processing
time predictor. It is applied to both phases through the existing
`Schedule.runWithOptions`. Default dispatch passes an empty order and allocates
no permutation metadata.

`runWithOptions` validates a supplied permutation in linear time before launching
callbacks. Only the next dispatch slot is remapped. Worker arrays, statements,
manifest roots, per-proof estimates, traces, errors and output bundles remain
indexed by the original ordinal. Both the reused single-lane pool and independent
lane pools follow the same mapping. Existing worker budgets, admission waiting,
error cancellation and thread joins remain the authority. No alternative
scheduler loop or new worker lifetime is introduced.

The complete stage-one join and sealed manifest still precede every stage-two
challenge. Truth-first scheduling cannot draw a challenge from a partial root
set. It neither weakens local REG/OWNER closure nor changes the global RAM/KIO/
wire obligations. Public proof order remains CPU first then truth providers.

The memory cap still admits against estimated in-flight work. It does not bound
allocator-retained memory, setup caches, parked files, mappings or process RSS;
an oversized job is admitted alone. A priority change can change peak resource
use even when every proof byte is identical. Declared cells omit effects such
as lifted-tree hashing and per-component parallelism, so only full-block results
can justify a throughput recommendation.

Focused Safe/Fast tests cover permutation rejection and allocation failure before
callbacks, serial reused-pool ordering, parallel exactly-once work, ordinal
estimate/trace indexing, cap enforcement and joined cancellation. Additional
physical tests prove mixed CPU/Keccak/ADD/DOUBLE workloads under truth-first
scheduling and require exact proof, claim, request and manifest parity followed
by fresh verification. A schema7 prefix4 sweep also requires all 11 retained
proof/public artifacts to match and verifies both modes in separate processes.
The observed prefix walls are 21.46s and 22.65s while compilation was active;
these do not establish a speedup.

Full Safe services and terminal regression passes. A current-shape full-block
ABBA comparison completes with all four full blocks verified and byte-identical.
Performance promotion is rejected on the current evidence. Full-block outcomes must distinguish correctness
from performance qualification. Current nominal 96-bit q70/P26/fold1 is only a
control suite; this scheduling change does not qualify whole-protocol 128-bit
security.

Functional receipt: `vectors/reports/rv64-word16-execution-20261101/truth-dispatch-ls7-functional-v1.json`.


## Full-block result and decision

Every run proves104,253,913 retirements with25 CPU and5 truth proofs. All34
proof/public artifacts match the LS7 complete control, and all four fresh
receivers accept completed block coverage and the43-byte output.

| Mode | Wall observation | Proving observation | Charged peak footprint | Qualification of timing |
|---|---:|---:|---:|---|
| A0 manifest | 153.05s | 131.41s | 29.069GB | Existing compiler/test overlaps; excluded |
| B0 truth-first | 158.37s | 136.52s | 39.980GB | Existing compiler/test overlaps early part; excluded |
| B1 truth-first | 163.60s | 142.53s | 39.963GB | Team activity quiet; external background processes remain |
| A1 manifest | 159.79s | 138.57s | 27.888GB | Team activity quiet; external background processes remain |

There is no positive throughput result. B1/A1 differs by2.38%, within the prior
7.5% baseline spread, with only one clean-team sample per mode. Neither a speedup
nor a precise throughput regression is qualified. Truth-first's substantially
higher observed footprint repeats in both B runs. It remains an optional
experiment, **off by default**; manifest dispatch is the recommendation.

The in-run accounting explains why simple priority order was unlikely to help.
A1 stage two sums206.523 worker-seconds across a103.699-second two-lane span,
about99.58% occupied-lane efficiency. This is job balance, not CPU-core usage.
B1 sums208.739 worker-seconds across106.670 seconds (~97.84%). Reordering cannot
remove FFT, hashing or constraint work. Its largest truths execute with more
CPU commitments still retained; the memory profiles are consistent with greater
concurrent pressure. An isolated causal account would require further profiling,
which is not needed to reject default promotion on these observations.

Exact commands, interference windows, observed per-phase lane occupation and
artifact assertions are in
`vectors/reports/rv64-word16-execution-20261101/truth-dispatch-ls7-full-abba-v1.json`.
The local CPU-delta monitor is pinned by hash; it contains no process arguments.
