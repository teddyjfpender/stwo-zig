# Small detached recursion: work in progress

Starting checkpoint: `51646b44`. This directory retains failures as well as
passing gates. The corrected version-2 development route proves two different
x7 statements under one identical serialized key and freshly verifies both.
The original version-1 admission failure remains retained below.

## Admission and dynamic register inputs

`detached-admission-first.log`: all nine guarded tests passed. The three groups
exercise the witness-free 39-component factory, expected-public statement claim,
and explicit detached development transcript. The factory's first compilation
took 46 seconds; public-input and transcript checks took six and five seconds.
Runtime was below 300 ms per group. These are construction/semantic checks,
not recursive-proof acceptance.

`dynamic-register-focused-gates.log`: all 20 tests passed, including test-root
declarations. The named gates cover row11 byte decomposition/export, native-sum
graph equality across changed register values, and row15's exact consumption of
those bytes. Native/CSP proof parameters and defaults are unchanged. The outer
statement/public-source identities are versioned for the added lookup events.

The focused frontend commands now filter their own cases and enforce minimum
test counts. The broad test inventory still owns transitive coverage. Compilation
fell from approximately 60/21/20 seconds to 13/6/6 seconds for these three gates;
each focused runtime was at most 500 ms. These are observations from one build
of each version, not repeated benchmark medians.

Retained failures explain the subsequent edits:

- `row11-semantic-gate-first.log`: enum arithmetic inferred a one-bit result.
- `row11-semantic-gate-second.log`: the intentionally old AIR digest rejected
  the new event structure; the measured digest was then pinned.
- `dynamic-register-semantic-gates.log` and the two `*-semantic-direct.log`
  files: an obsolete seven-event compatibility guard rejected the nine-event
  AIR, and the new graph regression omitted the required binary capacity lane.
  The direct retained test binaries identified the exact errors without a new
  compilation. Both causes are repaired by the passing focused run above.

## First detached artifact and retained failures

`candidate-x7-a-verifier.log` records a real 91,035-byte recursive proof accepted
in a separate process with no native inputs. Verification took 15.919 ms and the
verifier request took 17.151 ms in this single observation. The producer reports
403.233 ms detached preparation and 863.204 ms detached proving, in addition to
its existing native-assisted parity route. These are development-profile
measurements, not a production-security or optimized full-request benchmark.

`candidate-x7-a-hostile-replay.json` records 12 fresh-process cases: genuine
acceptance and rejection of changed claims, balanced claim/provider tampering,
malformed proof encoding, changed proof data, a wrong key pin, and a different
canonical expected statement. The maintained command is
`scripts/riscv_segment_v2_detached_gate.py`; retained binaries and source snapshots
pin this historical version.

`candidate-x7-b-producer.log` rejects a different x7 value under the same key.
`candidate-x7-fixed-circuit-diff.json` localizes the mismatch to row13's
preprocessed statement-hash call words; other preprocessing rows and graph
structure agree. The correction moves those words into committed witness data
and binds each indexed group to expected calls derived by the shared native
authority-preimage emitter. `row13-dynamic-fourth.log` passes both focused tests;
the corrected real-proof result is recorded below.

The memory audit also found that Span memory digest fields were not equated to
the actual sparse-snapshot digest fields. Canonical admission and 16 independent
AIR graph equalities now implement that binding. `memory-binding-semantic-v1.log`
passes 42 tests, including every one-sided digest mutation. The detached transcript is
version 2; the retained first artifact uses version 1 and must be replayed with
its pinned historical verifier.

## Corrected same-key complete proofs

`same-key-v2.json` records two distinct expected statements and proofs with the
same serialized key, SHA256
`0c8de0d9530af6194acbb40e7657ce4b115cf33bb2603958b7ca69b97eb30c85`.
Both fresh verifier processes accepted without native inputs. The x7-a proof
has 93,420 bytes and verified in 17.069 ms; x7-b verified in 15.183 ms.
These are individual observations, not medians. The producer still runs the
native-assisted parity oracle before producing the additional detached proof.

`candidate-v2-x7-a-hostile-replay.json` passes all 12 fresh-process cases,
including the other canonical expected statement. This checks a fixed tiny
fixture profile across changed register values; arbitrary sparse topology or
production security is not implied. The source-pinned rebuilt verifier also
passes the 12 retained cases in `same-key-v2-current-hostile-replay.json`.

`detached-v2-gates-first.log` passes all 12 guarded integration tests and builds
the standalone verifier. `core-geometry-oom-focused-v4.log` passes both named
tests, including exhaustive allocation-failure sweeps for column concatenation
and both mask-construction modes. `detached-boundary-review.md` records the
separate code review and its practical limits.

## Two actual children on CPU and Metal

`two-child-cpu-1/` and `two-child-metal-1/` retain both actual proofs for the
same completed 98-instruction memory workload. Child 0 covers cycles [0,64),
child 1 covers [64,98). Native prover output is destroyed before fresh native
decoding; each outer candidate and preparation owner is destroyed before the
next child. The producer process exits before detached bundle verification.

Both backends produce byte-identical per-child keys, expected wires and outer
proofs. Each backend passes 17 fresh-process cases, including complete-job
coverage, sparse snapshots, boundary clocks and lineage, plus rejection of
swapped, duplicated and missing children. See the two
`two-child-*-1-hostile-pair-replay.json` files. This is a verified two-proof
bundle; it is not a succinct recursive parent proof.

Individual producer-process observations: CPU 7.91 seconds, Metal 6.55 seconds.
Child outer proofs have 93,479 and 92,901 bytes. CPU fresh per-child verification
took 16.261 and 15.603 ms. CPU maximum RSS was 1,070,563,328 bytes; Metal maximum
RSS was 591,003,648 bytes. The OS separately reported Metal peak memory footprint
of 1,418,905,472 bytes: RSS must not be substituted for total device-related
footprint. Raw `/usr/bin/time -l` output is retained. These are development-profile
observations, not repeated performance benchmarks.

`detached-child-recording-second.log` passes all five guarded tests: the factory
records all 39 AIRs with 41 symbolic claim inputs, and a retained real child
survives input destruction, transcript/capture replay and tamper rejection. Its
recording contains 100 operations, 1,484 Poseidon calls, 2,276 sampled values,
6,348 queried values, 16 FRI layers and three queries. That gate precedes actual
composition evaluation and parent AIR admission; it does not replace either.

`detached-child-composition-first.log` then passes actual composition evaluation
against that genuine proof. The graph has 10,072 inputs, 39,769 nodes and 52
outputs. Every one of the 41 claim inputs and all four limbs of a composition
sample are independently mutated and rejected. The combined real-child replay
and composition gate runs in about one second with 18 MiB reported RSS, after a
57-second focused compilation. Parent authentication of the graph's dynamic
public-boundary input remains required.

## Required complete-proof checks still pending

`detached-child-prefix-third.log` passes the genuine-child gate with actual
typed transcript-prefix rows: 60 operations, 247 Poseidon calls, 54 fixed and
984 dynamic payload words, 1,000 declared input uses and two public-boundary
challenge exports. The gate checks lookup tuples and multiplicities, keeps
dynamic values out of preprocessing, and checks the exact transition to the
captured PCS suffix. It runs alongside composition and fresh verification in
one second with 18 MiB reported RSS (57-second compilation). Parent activation
remains false until consuming arithmetic, provider closure and a parent proof
pass. The first two attempts retain compile failures, corrected by explicit
coordinate narrowing and matching the existing infallible row constructor.

`sparse-specialization-before-first.log` retains the no-proof reproduction:
values 13 and 14 have identical address topology and 2,255 graph nodes but
different constant anchors; value 269 adds a seventh continuation term and
changes the graph to 2,263 nodes. The 12-test gate takes 450 ms after seven
seconds of compilation. Its exact pre-fix test is retained in
`sparse-specialization-before.patch`; this is evidence of the remaining defect,
not acceptance of dynamic memory admission.

The single-command lifecycle gate now also passes 17 fresh-process cases on
both backends. `lifecycle-cpu-1-process.json` and
`lifecycle-metal-1-process.json` retain exact commands and wall times of 8.076
and 6.282 seconds. Producer processes exit before verification; caller allocator
payload is zero before each native decode and after each outer producer is
destroyed. The gate checks the independent key pins and expected inputs, actual
Metal dispatch, and unchanged artifact hashes. `lifecycle-guard-checks.json`
retains rejection of invalid lifecycle metadata and output reuse. Runnable
instructions are in the small-recursive benchmark document. Verifier-only
replays do not hold the heavy-job lock.

The maintained candidate producer and detached verifier share one explicit
transcript definition. A candidate is not a verifier receipt. The corrected
same-key check has fresh-process evidence. Its fixed projection includes the exact Tree0
root and active lowering anchors; dimension equality alone is insufficient.

Sparse-memory values and zero-byte elision remain a separate dynamic-circuit
admission issue. The next milestone is the actual recursive parent: bind the
detached transcript's dynamic public inputs, context/hash boundaries, claims and
captured openings into its active AIR. No recursive parent, 2/4/8-segment ladder,
or production-security result is claimed yet.

The earlier CSP diagnostic's quiet-host admission remains unmet. New outer
admission changes do not establish CSP performance promotion.
