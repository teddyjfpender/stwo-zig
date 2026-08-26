# ADR-0022 — Authenticated Poseidon layout benchmark boundary

**Status:** proposed
**Date:** 2026-08-06

**Classification:** experimental benchmark policy; not accepted for production

## Context

[ADR-0020](0020-cost-frontier-materialization-proposals.md) records a complete
one-edit Poseidon materialization neighbourhood whose 126 retained non-seed
cuts have exactly the compatibility seed's structural vector. That plateau is
useful negative evidence, but it does not show whether the position of a cut
changes locality or execution time. The current production Poseidon component
cannot answer that question fairly: it uses a separate static evaluator for
the compatibility layout, while no retained proposal has an executable CPU or
Metal path.

A benchmark that compares the production static evaluator with a newly written
candidate interpreter would mostly compare implementations. A benchmark that
includes the hash-component shell, LogUp, commitments, or the PCS would add
work that is invariant across these cost-equivalent cuts and could hide the
small boundary under study. Conversely, timing only one proposal chosen by
digest order would make an arbitrary authenticated ordering look like a design
choice.

H-010 therefore needs a narrow, authenticated experiment. It must give every
ranked layout the same evaluator, inputs, phase boundaries, sample schedule,
and failure policy; keep correctness evidence ahead of timing; measure actual
memory rather than relabeling H-009's theoretical live-node coordinate; and
make it impossible to mistake a microbenchmark result for a production layout
decision or proving-speed claim.

## Decision

Define `stwo.typed-air.benchmark.poseidon2-layout-retained-v1` as an
experimental, CPU-only benchmark protocol. It compares four authenticated
materialization cuts with one common retained interpreter. It is not an
accepted production policy and cannot activate a layout.

### Authenticated source and fixed identities

Every run must decode and authenticate the checked H-009 binary
[`frontier.stwairm`](../artifacts/h009-poseidon2-cost-v1/frontier.stwairm).
The benchmark fails closed unless its bytes and decoded fields match all of the
following:

| Identity | Required value |
| --- | --- |
| artifact format | `STWAIRM-v1` |
| artifact SHA-256 | `5ead00cfcb8cfd396836be9cc3a79ed80bfb0b8bc7913a1c6ab38dbcff879494` |
| proposal policy | `stwo.typed-air.materialize.cost-frontier-v1` |
| fixed cost scope | `stwo.typed-air.cost.poseidon2-permutation-direct`, version 1 |
| semantic digest | `9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed` |
| frontier identity digest | `d85aa12bb4de8b676d88e184558bf2ef047cf286fab2f6b7ee4e3825001faa68` |
| fixed-program digest | `ef32024ba1d25b470c217ef96af95b52038948c67f6ac4ce1e14875bf68ea6a5` |
| cost-model digest | `12670408a3c3020c62d279c997338d9c427d0755697aca2a954f6a1d88a9ba11` |
| search-configuration digest | `32dc4c0b5e265c74b159a6e661d4f6f0b06f3b54d62efe286364b5dae92db8ed` |
| result digest | `7948117553242d3154a8bd09ca1664c4bf6e5cbcc515a4ce80461cf544d39193` |
| retained non-seed proposals | 126, untruncated and all baseline-equivalent |
| common structural vector | 426 materializations, 445 main columns, 430 direct roots, 8 interaction columns, 3,460 direct nodes, 1,080 direct multiplications, 445 committed reads, 2,171 semantic witness nodes |

The H-009 artifact remains the proposal authority. A benchmark report may copy
these identities for provenance, but may not reinterpret or replace them.
Before lowering, the harness must also recompute the digest of the compile-time
`typed_poseidon2_fixed_direct` program and require one three-way equality among
that value, the source module's canonical digest, and the decoded H-009
fixed-program digest. Authenticating only the artifact field or only aggregate
fixed-root counts is insufficient.

### Deterministic benchmark arms

The ranked experiment has exactly four arms:

| Arm ID | Class / ordinal | Proposal digest | Cut digest | Edit |
| --- | --- | --- | --- | --- |
| `compat-seed` | baseline / 0 | `7a585031ef8710d62adac55d1c2d8072c0b2a6ce82a562b4862d4329623a23ef` | `b10cb7f66e3519788ecec6edc4095541a24eaf642a3ed8877fbe87c85e8ba9c5` | seed |
| `removed-q0` | frontier / 85 | `997d7236203de34953b8479ea2773a0772737d6e7f81c08537f8bd744f5ccd44` | `96f45498a15b2313ca83a9f5bc8a38f74c620f2712ca219bf440cb30dbe1e788` | swap `266 -> 240` |
| `removed-q50` | frontier / 92 | `ae33d31eab62c10a8be6826a6e739c6e30dddf154eec22d10194e3583fa37e23` | `0f339a827261aa19693617a6d782d8b02a49a6930fd75ea512c9bb62a59ea90e` | swap `1517 -> 1485` |
| `removed-q100` | frontier / 60 | `662338db02cbb0e7e1e4eb7f486b2f6a05087e96f8d3597ca50dd667faa9ae6a` | `a2b77acaaf4977012e6dfc17fed31856b906c1e221999d4d52932922cd425f20` | swap `2039 -> 2007` |

Every non-seed arm is a pass-1 edit with 426 selected values and parent cut
`b10cb7f66e3519788ecec6edc4095541a24eaf642a3ed8877fbe87c85e8ba9c5`.
Each must reproduce the complete common structural vector, not merely its
materialization and node counts.

The three non-seed arms are derived, not hand-picked. Sort all 126 retained
proposals by `(removed_value_id, proposal_digest)` in ascending canonical byte
order. For quantiles `q = 0/1`, `1/2`, and `1/1`, select zero-based index
`floor(q * (count - 1))`. For the authenticated v1 frontier these are indices
0, 62, and 125, with removed `ValueId`s 266, 1517, and 2039 respectively.
The implementation must recompute this selection and require the exact table
above. A changed count, tie, ordering, ordinal, digest, edit, or cut is an
identity failure, not a reason to silently choose a nearby arm.

This selection spans the beginning, middle, and end of the materialized
semantic-DAG positions while keeping the experiment bounded. Digest order is
only the stable tie-breaker; it is not an optimization score.

### One common CPU evaluator

All four ranked arms use the same executable and the same scalar M31
interpreter. The evaluator identity is
`stwo.typed-air.poseidon2-retained-cpu-evaluator-v1`. Its source-closure and
executable SHA-256 values are recorded by each timing run; a source or binary
change creates a new evidence cohort even if the protocol ID is unchanged.

For each arm the harness must:

1. independently revalidate the canonical cut against the authenticated
   semantic program, degree-three policy, fixed program, and candidate-relative
   column mapping;
2. compile the arm's semantic witness schedule and the complete fixed-prefix,
   materialization-equality, fixed-suffix direct program through the same
   implementation;
3. preallocate indexed scratch once per child and perform no per-row allocation;
4. write the sixteen base state values and three fixed roles, then compute and
   write the arm's 426 ordered materializations into the 445-column main trace;
5. evaluate every row of the 3,460-node direct DAG into one 3,460-element
   row-local scratch array without slot reuse, then fold all 430 ordered roots
   into a deterministic sink; and
6. retain values until the end of their respective witness or direct pass.

“Retained” is a measured implementation choice, not H-009's idealized
39-live-node schedule. The full indexed arrays make the first comparison easy
to audit and keep layout selection separate from liveness optimization. A
streaming, register-allocated, vectorized, JIT, or arm-specialized evaluator is
a different evaluator cohort and cannot be pooled with v1 retained results.

The current production static Poseidon evaluator may run as an explicitly
labelled `production-static-control`, but it is unranked. Its code shape,
storage behavior, and boundary differ, so its timings cannot establish a
candidate win or loss. It does not participate in arm selection, rotation,
summaries, or H-010 acceptance.

Metal candidate execution is unsupported. A Metal proof may continue to
exercise the unchanged compatibility component, but no H-010 report may label
that as execution of any ranked arm or combine it with the CPU distributions.

### Deterministic input vector

Correctness inputs are a deterministic artifact, separate from timing
evidence. Its protocol identity is
`stwo.typed-air.benchmark.poseidon2-layout-vector-v1`. The implementation must
define one canonical, length-delimited byte encoding containing the vector
format version, semantic digest, generator identity and domain, log size, row
count, sixteen M31 input words, the three fixed roles, and sixteen expected M31
output words for every row, followed by a SHA-256 over the preceding bytes. No
native struct bytes are hashed.

The canonical encoding is:

```text
magic                 8 bytes  "STWAIRB\0"
format_version        u16 LE   1
generator_id_length   u16 LE
generator_id          bytes    "stwo.typed-air.benchmark.sha256-counter-v1"
semantic_digest       32 bytes
log_size              u32 LE
row_count             u64 LE   exactly 1 << log_size
rows[row_count] {
  input_state[16]     u32 LE   canonical M31 representatives
  enabler              u32 LE
  wide                 u32 LE
  io                   u32 LE
  expected_state[16]  u32 LE   independent typed-reference permutation
}
seal                   32 bytes SHA-256 of every preceding byte
```

Let `P = 2^31 - 1`. For state lane `lane` in row `row`, compute

```text
SHA-256(
  "stwo-zig/typed-air/h010/poseidon2-vector-value/v1\0" ||
  semantic_digest || u32_le(log_size) || u64_le(row) || u16_le(lane)
)
```

interpret digest bytes 0 through 3 as an unsigned little-endian integer, and
store that integer modulo `P`. Set `enabler = 1`, `wide = row mod 2`, and
`io = 1 - wide`. No host RNG, native struct layout, locale, or floating-point
operation participates. Generator tests must pin byte-exact small vectors,
boundary field values, independent expected outputs, and full digests for every
default log size. The benchmark reads and authenticates the checked bytes for
logs 10 and 14; random generation is never in a timed region.

The deterministic log-10 and log-14 vectors are checked repository artifacts
under [`h010-poseidon-layout-v1`](../artifacts/h010-poseidon-layout-v1/).
The readable [`index-v1.tsv`](../artifacts/h010-poseidon-layout-v1/index-v1.tsv)
pins the complete vector metadata plus rows 0, 1, and the final row for each
checked vector; its file SHA-256 is
`1c881a3a944794943f872ea85678a4809db68a96021b06abbc15ef42d878fd19`.
Log 10 is
143,490 bytes with file SHA-256
`2d90fa647d55758f1fdf7be46de5232ee006ac3682ab0371ec1108c95c8f14ee`;
log 14 is 2,293,890 bytes with file SHA-256
`b2f84aa4ecc9f017932a2ca81fd89060d1fccb8bfaf90c9843ac9013cb6f83d8`.
Log 18 remains an opt-in resource diagnostic:
unless its much larger STWAIRB file is separately reviewed and checked, the
child deterministically regenerates and seals its stream, labels it
`generated_opt_in_uncommitted_non_receiptable`, and its observations cannot
enter an H-010 receipt.
Wall-clock and RSS reports remain uncommitted output under `zig-out/` by
default. A later immutable H-010 receipt may name the SHA-256 of selected
default reports without making their timing values a semantic, layout, proof,
or production identity.

### Measured boundary and timers

The required default log sizes are 10 and 14. Log size 18 is an explicit
opt-in stress run because its 445 main and eight interaction columns describe
475,004,928 committed bytes before interpreter scratch and process overhead.
It cannot replace either default size. Log sizes 4 and 6 remain correctness
fixtures and are not timing evidence because setup dominates them.

Each fresh child reports three non-overlapping monotonic-clock durations in
integer nanoseconds:

- `setup_ns` — artifact decode and authentication, arm derivation and complete
  revalidation, program lowering, scratch/trace allocation, and plan
  construction, including construction of the prepared witness/direct
  capabilities; process launch, vector-file read/authentication, and teardown
  are outside the timer;
- `witness_ns` — copy the checked base inputs and fixed roles into final trace
  storage, execute the common semantic witness schedule, and write the 426
  selected materializations; and
- `direct_ns` — execute all 3,460 direct nodes and fold all 430 roots over every
  row into the observable sink.

Reference comparison, digesting the completed outputs, report serialization,
and mutation tests are deliberately outside these timers. The direct root fold
is inside `direct_ns` because it prevents dead-code elimination and represents
consumption of every constraint result. No combined “prover time” or synthetic
weighted score is a primary H-010 metric.

Peak memory is the operating system's high-water resident set for that fresh
child, not an allocator estimate and not the modeled 39-node coordinate. The
parent records the per-child native `rusage`/equivalent value, its platform
unit, and normalized `peak_rss_bytes`. The platform adapter must have a unit
test against a known allocation before it can emit admissible results. If
per-child high-water RSS is unavailable or ambiguous, the run fails rather
than reporting zero.

### Sampling and summaries

For each required log size, run the four ranked arms serially in fourteen
rounds: three warmup rounds followed by eleven measured rounds. Round `r`
launches arm indices in the rotation
`[(r + 0) mod 4, (r + 1) mod 4, (r + 2) mod 4, (r + 3) mod 4]`. Every arm/sample
pair runs in a fresh child process. No arms run concurrently, and the same
ReleaseFast executable, vector bytes, environment allowlist, host, power
state, and worker count apply to the full cohort.

Warmups execute all authentication and correctness checks and fail the cohort
on error, but their timings are stored separately and excluded from measured
summaries. All eleven measured values are retained in launch order. For each
of `setup_ns`, `witness_ns`, `direct_ns`, and `peak_rss_bytes`, report:

- the raw eleven unsigned integers;
- median (the sixth value after ascending sort);
- median absolute deviation, computed as the median of the eleven absolute
  deviations from that raw median;
- minimum; and
- maximum.

No sample may be discarded as an outlier. Pairwise deltas may be derived by
round for diagnosis, but raw median/MAD/min/max remain authoritative within an
uncommitted timing report. Floating-point speedup ratios, significance tests,
and “winner” labels are interpretations, never benchmark identity.

### Correctness and mutation prerequisites

Timing admission occurs only after a non-timed preflight passes for all four
arms:

- the H-009 artifact, fixed program, semantic program, cost model, selection
  algorithm, proposal digests, and cut digests authenticate exactly;
- each cut independently passes reachability, topology, degree, gate,
  row-mask, fixed-column non-aliasing, output-completeness, and ordered-mapping
  validation;
- on pinned boundary vectors and every row of each admitted timing vector, all
  sixteen permutation outputs equal the independent typed Poseidon reference;
- all 430 direct roots evaluate to zero before folding;
- seed and proposal arms agree on semantic outputs, while their distinct
  materialization placements remain bound to their own cut identities;
- for every arm, one-at-a-time mutation of each of its 426 materialization
  cells on a canary row makes at least its owning equality root nonzero;
- one-at-a-time invalid mutations of `enabler`, `wide`, and `io` are detected
  by the fixed roots, including the mutual-exclusion case; and
- one-byte corruption campaigns against the vector seal, proposal digest, cut
  digest, fixed-program digest, and report arm identity reject.

Every measured child reauthenticates its vector before `setup_ns`, reauthenticates
its arm while measuring setup, authenticates and validates both prepared hot-loop
capabilities before their phase timers, then checks the direct sink,
semantic-output digest, and trace digest after them. The vector seal, call
digest, and semantic-output digest come from the independent production
reference path. Per-arm trace digests are candidate-layout regression pins:
they detect implementation drift but are not independent correctness oracles.
Correctness authority comes from the independently recorded expected outputs
plus all 430 direct roots evaluating to zero.

### Failure policy

Authentication failure, selection drift, a failed root, output mismatch,
mutation escape, allocation or arithmetic error, non-monotonic clock, child
signal or nonzero exit, missing RSS, report-schema error, or missing sample
invalidates the complete host/log-size cohort. A failure is recorded with its
arm, round, phase, and stable error code. It is never represented by a zero
duration, omitted sample, partial summary, or substitution from another run.

Automatic retries are forbidden. An operator may start a new run ID after
recording the failed run and reason; the new report does not overwrite or
silently merge with the first. Log-size-18 resource failure does not invalidate
a complete default log-size-10/14 report, but the opt-in stress report must
remain explicitly failed rather than absent if it was requested.

### Report schema and evidence classes

The report identity is
`stwo.typed-air.benchmark.poseidon2-layout-report-v1`; its JSON
`schema_version` is 1 and its exact `kind` is
`stwo-typed-air-poseidon-layout-benchmark`. The timing writer emits one
self-contained document per host run with:

1. `schema_version`, `kind`, protocol/evaluator/vector identities, run ID, and
   `experimental_uncommitted_timing` classification;
2. repository commit/tree/clean state; exact source-closure, executable, H-009
   artifact, and deterministic-vector byte counts and SHA-256 values;
3. Zig version, optimization mode, target, OS/kernel, CPU model, logical and
   physical core counts, memory, power-state declaration, environment
   allowlist, and monotonic-clock/RSS adapters;
4. the exact arm table and recomputed quantile-selection evidence;
5. log size, rows, structural geometry, scratch sizes, worker count, warmup
   count, measured count, and complete rotated launch schedule;
6. every warmup and measured sample with round, launch ordinal, child exit,
   the three raw durations, native and normalized RSS, semantic-output digest,
   trace digest, direct sink, and validation status;
7. the integer median/MAD/min/max summaries for each ranked arm and metric;
8. optional, separately labelled production-static-control observations; and
9. a complete failure array and a final validity flag that is true only when
   every required field and sample passes.

Unknown schema versions fail closed. Required integer fields may not be
floating point. JSON object order is not an identity; if a report is later
pinned by a receipt, that receipt names the SHA-256 of the exact stored bytes.

The deterministic vector answers “what exact computation was run?” and may be
a checked repository artifact. The timing report answers “what happened on
this host at this time?” and is mutable experimental evidence until a later
receipt deliberately freezes exact bytes. Neither class changes the canonical
program identity from
[ADR-0021](0021-backend-neutral-poseidon-program-identity.md).

### Explicit exclusions

The ranked boundary includes only candidate main-trace witness generation and
the fixed 430-root Poseidon permutation direct AIR. It explicitly excludes:

- the surrounding sparse-Merkle/hash-component shell;
- LogUp relation construction, interaction-column evaluation, and claims;
- preprocessed columns and guest precompile call plumbing;
- circle interpolation, LDEs, and Merkle commitments;
- quotient construction, PCS/FRI, decommitment, grinding, and proof encoding;
- transcript/public-statement construction and verifier time;
- proof size and end-to-end proving time;
- component scheduling or parallel proving; and
- Metal candidate execution.

The eight interaction columns remain in the authenticated H-009 structural
identity but are not allocated or evaluated by this microbenchmark. Reports
must therefore say `proof_executed = false`,
`metal_candidate_execution_supported = false`, and
`production_layout_changed = false`. A result is evidence about this CPU
interpreter boundary only; it is not a proving-speed, proof-size, verifier,
Metal, or production claim.

### Isolation

The selector, vector reader, retained interpreter, child runner, and report
writer live behind an explicit test/tool build target. They are not exported
from the production AIR language facade or reachable in the constructed
CPU/Metal executable module graphs or normal proving commands. The repository's
conservative lexical product-closure scan does traverse the frontend's
test-inventory imports; it therefore enumerates the test-only generated
artifact-module names without resolving them to production sources. This is a
declared lexical exception, not executable reachability. The H-009/H-010
artifacts remain available only through dedicated test/tool bridges and exact
source-conformance allowlists.

Timing output is written atomically beneath `zig-out/`; check mode never
writes, and a requested output path must not overwrite an existing run. The
production static control is called through a read-only adapter and cannot
consume a proposal cut. No generated benchmark vector, selected cut, timing,
or host profile may become witness, constraint, layout, transcript, statement,
verifier, or product-build authority by import.

### Staged implementation

Implementation proceeds in fail-closed stages:

1. **Identity and selector:** decode the checked H-009 artifact, recompute the
   three quantiles, pin the exact four-arm table, and exhaustively test field
   corruption and ordering drift.
2. **Deterministic vectors:** implement the canonical generator, encoding,
   check/update workflow, independent reference outputs, and byte-exact
   goldens for logs 10 and 14; add log 18 without making it a default gate.
3. **Untimed common evaluator:** implement one retained CPU interpreter for
   every arm, prove root-by-root/output equivalence, run the complete
   materialization/fixed-role mutation matrix, and verify no production
   executable/runtime import changes.
4. **Isolated measurement:** add fresh-child execution, exact timer boundaries,
   rotated rounds, RSS normalization tests, atomic JSON emission, schema
   validation, and injected failures for every fail-closed path.
5. **Experimental run:** on one clean immutable snapshot, collect complete log
   10 and 14 reports with three warmups and eleven samples; optionally collect
   log 18 separately. Record all raw values and environmental provenance.
6. **Review, not promotion:** audit the harness and evidence. Closing H-010
   means the boundary was measured correctly; it does not select or activate a
   layout. Any proposed promotion requires a new accepted ADR, production
   implementation, full proof-path equivalence, and the complete
   [performance contract](../PERFORMANCE.md).

## Consequences

- Every ranked layout is authenticated to one H-009 frontier and executed by
  one implementation, so arbitrary digest order and implementation skew cannot
  masquerade as layout evidence.
- Minimum/lower-median/maximum removed-`ValueId` representatives give
  deterministic positional coverage without timing all 126 plateau cuts.
- Separate setup, witness, direct, and RSS distributions expose shifted cost
  that one elapsed-time headline would hide.
- Fresh children provide a meaningful process high-water mark and prevent one
  arm's arena from inflating or warming another arm's sample.
- The retained interpreter is intentionally simple and memory-heavier than an
  ideal streaming schedule. Its results do not predict a future specialized
  evaluator without a new cohort.
- Logs 10 and 14 keep the default experiment practical; opt-in log 18 tests
  memory scaling without making a large allocation a routine gate.
- The narrow boundary can discriminate layout locality, but it deliberately
  cannot answer whether a proposal improves end-to-end proof time.
- No production witness, constraint, layout, protocol, transcript, verifier,
  backend capability, or program identity changes.

## Rejected alternatives

- **Rank all 126 proposals:** rejected for the first experiment because every
  proposal has the same structural vector and exhaustive timing multiplies
  noise and cost without a principled prior.
- **Choose first/middle/last proposal digests:** rejected because proposal
  digests authenticate content but do not describe semantic-DAG position.
- **Compare candidates directly with the production static evaluator:**
  rejected because implementation differences would confound the layout.
- **Use H-009's 39-node streaming peak as measured memory:** rejected because
  it is a theoretical schedule, not resident-set telemetry.
- **Include commitments or a full proof immediately:** rejected because no
  proposal layout has a production proof path and invariant downstream work
  would obscure the first controlled comparison.
- **Time Metal by falling back to CPU composition:** rejected because fallback
  is not Metal candidate execution and would misstate backend capability.
- **Keep only best samples or retry failures automatically:** rejected because
  both practices bias small differences and erase operational evidence.
- **Commit timing JSON as a canonical artifact by default:** rejected because
  wall time and RSS are host observations, not semantic authority.
- **Promote the fastest arm from H-010:** rejected because this boundary omits
  most of the prover and has no production or Metal candidate implementation.

## Revisit when

Reopen or version this decision when the H-009 artifact or selected arm table
changes; a non-plateau frontier supplies a principled structural candidate; a
streaming, SIMD, compiled, or otherwise different common evaluator is ready;
Metal can execute the same candidate layouts without fallback; the deterministic
vector or memory adapter requires a format change; or a candidate is proposed
for production proof-path integration.

Production consideration additionally requires an accepted layout ADR,
canonical program-identity treatment, generated-versus-current proof
equivalence, complete commitment/PCS/proof-size/verifier measurements on every
supported backend, a rollback path, and explicit acceptance of any regression.
