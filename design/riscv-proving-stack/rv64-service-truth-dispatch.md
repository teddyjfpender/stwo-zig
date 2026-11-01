# Optional truth-first service dispatch

This recovers the useful scheduling idea from `92f244fec` onto current LS7
`fe3b29fc0`, without replacing the scheduler or owned CPU/truth worker. It is
producer-only, explicitly enabled with `--truths-first`, and **off by default**.
No AIR, proof suite, public statement, transcript or geometry changes.

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
by fresh verification. A schema7 prefix4 sweep also requires all11 retained
proof/public artifacts to match and verifies both modes in separate processes.
The observed prefix walls are21.46s and22.65s while compilation was active;
these do not establish a speedup.

Full Safe regression and a current-shape full-block ABBA comparison are the
remaining measurement gates. Full-block outcomes must distinguish correctness
from performance qualification. Current nominal96 q70/P26/fold1 is only a
control suite; this scheduling change does not qualify whole-protocol128-bit
security.
