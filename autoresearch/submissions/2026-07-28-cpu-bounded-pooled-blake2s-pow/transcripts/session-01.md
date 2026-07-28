# Session 01: persistent pooled proof-of-work

## Objective and contract

The campaign objective was to produce a new, independently checked STWO
performance record and submit it without weakening proof correctness or any
resource guard. The current authoritative `core_cpu/small` frontier was pinned
at `78556fe7d3fa`, and the final acceptance unit was a complete S3 proof
transaction. A kernel-only speedup, an unverified proof, a resource regression,
or a local result without the repository's submission envelope would not
count.

The editable mechanism was prover-side proof-of-work. The protocol constraints
were fixed: the transcript prefix and difficulty input could not change; the
returned nonce had to verify; the lowest valid nonce had to remain stable so
proof bytes stayed identical; and the explicit dedicated-worker override had
to retain its behavior.

## Why this mechanism

The existing Blake2s channel could search in parallel, but its default path
created and joined operating-system threads inside a complete proof. The
prover already had a persistent `WorkPool`. On the small workload, repeated
thread lifecycle overhead was large enough to be worth attacking, while the
hash operation itself was already close to a fixed-cost primitive.

The selected design reused the existing pool only when all of the following
were true:

1. the channel was Blake2s;
2. proof-of-work difficulty was nonzero;
3. the user had not selected the explicit `STWO_ZIG_POW_WORKERS` override; and
4. a global prover pool was available.

Every other path continues through the existing channel implementation or the
generic scalar verifier loop.

## Exactness design

The Blake2s proof-of-work input has a constant 32-byte prefix for a given
transcript and difficulty, followed by an eight-byte nonce. Computing the
prefix once and feeding eight nonce candidates to the existing eight-way
fixed-block primitive removes redundant setup work.

Workers enumerate disjoint residue classes:

- worker `i` starts at nonce `i`;
- its stride is the active worker count;
- each iteration evaluates eight successive values in that residue class.

An atomic value begins at the maximum `u64`. A worker publishes a valid nonce
with `fetchMin`. Other workers continue only while their next nonce is below
the published bound. The caller waits for all scheduled jobs before loading
the result. This matters: returning the first raced result would verify but
could change proof bytes. Waiting until every residue class has exhausted the
range below the current minimum preserves the globally lowest valid nonce.

Two tests were added for this contract. The first compares pooled and existing
search results at several difficulties and worker counts. The second changes
the transcript and checks both results against the existing channel
implementation, preventing an optimization that accidentally ignores the
transcript prefix.

## First measured design and failure

The first current-frontier candidate reused the pool and let the active pool
size determine the number of proof-of-work jobs. It passed correctness and
produced byte-identical proofs. Its private S3 timing ratio was 0.947783 with a
95% interval of `[0.934571, 0.961326]`, so the time objective was significant.

It still failed G4. Peak RSS ratio was 1.162817, with a 95% upper bound of
1.164730. That is a terminal failure under the preregistered contract. The
result was classified audit-failed, and there was no push, PR, submission, or
record claim from that evidence.

This failure rejected the tempting conclusion that more workers were always
better. The complete-proof workload was small enough that full pool occupancy
added resource cost and contention faster than it added useful hash
throughput.

## Smallest repair

The repair changed only the active proof-of-work worker count:

```zig
const worker_count = @min(pool.workerCount(), 4);
```

Four was chosen as a bounded concurrency policy, not as a claim about all
hosts. It keeps three jobs on the existing pool and runs one job on the caller,
so there is no new operating-system thread lifecycle inside the grind. The
explicit override remains untouched.

Alternatives considered and rejected:

- keeping the uncapped pool was rejected by the measured RSS gate;
- returning the first valid raced nonce was rejected because it could alter
  proof bytes even when verification passed;
- replacing the shared pool with a new dedicated pool would retain the
  lifecycle cost that motivated the change;
- changing the transcript or proof format was outside the contract;
- tuning only a micro-kernel was lower leverage than eliminating redundant
  scheduling and fixed-prefix work.

## Final preregistered evaluation

One pre-timing invocation refused to run because the shell selected Zig 0.16.0
instead of the manifest-bound Zig 0.15.2. It emitted no timing samples or
verdict and left no judge lock. The environment was corrected before the
single statistical evaluation; this was not a significance rerun.

The final exact-frontier S3 run used 20 paired ABBA rounds. Results:

- Hodges-Lehmann time ratio: 0.914657;
- harness portfolio 95% CI: `[0.895716, 0.931916]`;
- independently reconstructed 95% CI: `[0.896952, 0.932478]`;
- 19 of 20 paired rounds faster;
- baseline median: 1.438375 ms;
- candidate median: 1.317000 ms;
- peak RSS ratio: 0.959330, upper CI 0.960609;
- energy ratio: 0.898412, upper CI 0.909402;
- proof bytes: 24,965 in both arms;
- proof digest:
  `91741aec956846d52e50f7b8fef3ac93195dbcd76cdb89e25ed33a148bea5700`.

Every timed proof verified, cross-arm proof bytes matched in every round, and
the pinned Rust Stwo oracle passed. G1 through G5 all passed. The independent
packet audit checked the report hash set, semantic provenance, statistics,
mutation control, and 54 of 54 artifact bindings.

## Publication path and infrastructure dead end

The candidate branch was pushed at exact commit `e46ff331588e`. The
authenticated remote queue was empty, and the authoritative frontier still
resolved to `78556fe7d3fa`.

Fork qualification was then dispatched. Source policy, locked-tree checks, and
all harness tests passed, but the canonical Ubuntu workflow failed before any
benchmark because generic `stwo-perf setup` attempted to build the Apple-only
Metal target. A separate board-scoped setup repair existed, but qualification
receipts require the canonical locked workflow and candidate diffs cannot
carry harness modifications. A duplicate dispatch was cancelled once the
deterministic failure was identified. No qualification receipt or remote
submission was claimed.

The remaining valid route is the documented PR submission path: package this
claimed verdict, note, and sanitized transcript on a branch containing only
the prover diff plus the generated submission directory. The local result
remains a claimed checkpoint until external validation and adjudication.
