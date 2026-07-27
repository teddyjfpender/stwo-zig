# Metrics v2 Delivery Goal

Status: normative implementation and closure contract for GitHub Issue #44.

## MVP release boundary

The 2026-07-21 maintainer scope decision separates the shippable Metrics v2
system from two host-authority activation operations. Issue #44 delivers the
five-class CPU/Metal workload universe, large-resource admission, ledger v3,
direct and span audit automation, shrinkage credit, complete resource vectors
and budgets, deterministic feed v3, search-health instrumentation, honest Rust
references, and the first same-host peer audit point. The calibration and judge
implementations ship fail closed in this MVP.

Two operational state transitions move to explicit follow-up contracts:

- GitHub Issue #47 freezes the five-class Metal calibration after an
  independently reproduced authenticated AOT bundle is available.
- GitHub Issue #48 pins the final RF release receipt, configures live branch
  authority, freezes RISC-V calibration, activates that board, and records the
  first signed judged supersession.

This transfer narrows the closure evidence below only where it requires live
authority state. It does not weaken a gate: while #47 is open, Metal calibration
remains `pending` and judged Metal G5 fails closed; while #48 is open, RISC-V
remains disabled and claimed rows remain visibly claimed. Periodic executions
of the shipped audit and peer-series workflows accumulate evidence after merge
without changing metric semantics.

This goal starts from the fully release-gated RISC-V adapter commit. It does not
weaken RF-01, the Rust Stwo correctness authority, pinned Sail/Spike RISC-V
evidence, or the locked-host judge contract. Metrics v2 is complete only when
the repository can measure large native workloads, adjudicate changes on the
locked M5 host, and derive every published score from replayable evidence.

## Objective

Replace the current optimistic, small-workload-biased scoring path with an
audit-anchored and resource-aware performance authority that:

1. exercises the CPU and Metal provers at geometries where their architectures
   differ materially;
2. derives classes, sampling, admission, anchors, and scoring from one manifest;
3. preserves append-only measurement provenance and makes corrections explicit;
4. credits only statistically supported, CI-conservative improvements;
5. measures time, memory, energy, and proof size as a vector;
6. compares stwo-zig with scalar Rust, SIMD Rust, and the pinned peer Metal work
   without changing metric semantics between series;
7. makes judged evidence, audit coverage, search power, and measurement cost
   visible to every feed consumer.

The system is not complete when a command merely runs. It is complete when the
same evidence passes repository tests, locked-host evaluation, publication
validation, and a clean replay from the recorded inputs.

## Non-negotiable invariants

- Proofs measured by the native lanes pass the pinned Rust Stwo oracle. RISC-V
  rows bind pinned Sail/Spike correctness evidence and pass independent Zig
  artifact verification. Cross-arm proof bytes remain identical.
- Frozen performance-authority epoch 3 files under
  `conformance/performance-authority/epoch-3/` are never edited.
- Historical ledger rows are never rewritten. New schema versions parse old rows
  deterministically and assign stable synthetic identities where required.
- A score never combines different machines, epochs, workload identities,
  protocols, security settings, timing scopes, or backend identities.
- CPU, Metal hybrid, Metal resident, and RISC-V remain distinct boards.
- A missing anchor, A/A dispersion, resource metric, oracle receipt, guard result,
  or judge signature fails a judged promotion closed.
- A larger resource profile is explicit at the CLI and in the report. It is never
  selected implicitly from input size and never disables structural limits.
- Direct audits and span audits run the full applicable oracle and regression
  guard portfolio. `guards_mode=none` is not admissible for score-bearing audits.
- Site and API output are pure projections of manifest, ledger, reference, and
  benchmark evidence. They do not recompute a different reward function.

## Authority model

### Manifest authority

`autoresearch/MANIFEST.json` owns the current metrics epoch's:

- class registry and display order;
- workload-to-class mapping;
- per-group build and report contracts;
- per-class sampling and wall-clock policy;
- per-board and per-class anchors;
- per-board and per-class A/A dispersion;
- dimensional budgets;
- audit cadence and span thresholds;
- peer reference pins and measurement commands.

Python code, workflows, renderers, activation checks, and CLIs must enumerate
classes from the manifest. No live consumer may keep a private
`small,wide,deep` tuple.

### Epoch authority

Adding `xlarge` and `huge`, changing score credit, and introducing dimensions
opens a new autoresearch metrics epoch. The epoch record binds:

- manifest digest;
- class set;
- workload identities;
- anchor reports and digests;
- A/A reports and digests;
- scoring algorithm identifier;
- shrinkage lambda;
- audit cadence;
- dimensional budgets;
- locked host identity.

Pre-epoch observations remain visible history but cannot be silently diluted by
new identity classes or included in the new suite geomean. Cross-epoch ratios are
never multiplied.

## W1: Large workload coverage

### Shared resource admission

One Zig module computes native proof admission for both the product CLI and the
native benchmark runner. It accepts a workload geometry and an explicit profile,
then returns an immutable admission receipt containing:

- profile name and version;
- committed trees, columns, rows, and cells;
- accounted bytes per committed cell;
- accounted bytes;
- cell and byte limits;
- the admitted result.

The standard profile retains conservative existing behavior. The reviewed large
profile admits at least wide Fibonacci `log_n_rows=20, sequence_len=100` on the
64 GiB M5 host. It still rejects unsafe arithmetic, unsupported domain logs,
excessive columns, excessive cells, and geometries beyond its memory budget.
Checked integer operations are mandatory.

The native report schema includes the admission receipt. Report consumers reject
the new schema if the receipt is absent, inconsistent with workload geometry, or
names an unknown profile.

### Classes and workloads

The new epoch contains these ordered classes:

| Class | Required native workload | Boards |
|---|---|---|
| small | existing manifest basket | CPU, Metal |
| wide | existing manifest basket | CPU, Metal |
| deep | existing manifest basket | CPU, Metal |
| xlarge | wide Fibonacci 100 columns x 2^18 rows | CPU, Metal |
| huge | wide Fibonacci 100 columns x 2^20 rows | CPU, Metal |

RISC-V keeps its own small/wide/deep set until its manifest explicitly adds
larger RISC-V classes. Shared class names do not pool board evidence.

Large classes use a bounded protocol suitable for long-running work: one warmup,
one sample per round, at least three rounds, no more than five rounds, and a
class-specific deadline. Every in-flight command receives the remaining
monotonic wall-clock budget as its timeout; the deadline is not checked only
between commands.

### W1 acceptance

- The CPU and Metal CLIs complete and verify log20 x 100 under the large profile.
- Standard-profile rejection and large-profile admission are unit tested at the
  exact boundary and above it.
- xlarge and huge are selected, measured, rendered, and scored dynamically.
- Adding an identity class with ratio 1 does not change a prior epoch's score.
- Each score-bearing new class has finite positive M5 anchor and A/A evidence.
- `autoresearch/TASK.md` and performance skills identify the large regime and
  cite the relevant peer techniques: batched constraint evaluation, SIMD type
  dispatch, threadgroup-tiled FFT, and single-submission GPU commit chains.

## Ledger v3 evidence model

Every new row has these canonical fields in addition to its objective, result,
environment, and resource vector:

- `row_id`: `sha256:` plus the SHA-256 of canonical v3 row JSON excluding
  `row_id`;
- `observation_id`: stable digest of `(submission_id, board, workload_class)`;
- `evidence_kind`: exactly `promotion`, `span_audit`, or `direct_audit`;
- `covers`: canonical JSON array of observation IDs, non-empty only for a span
  audit;
- `credit_replaces`: canonical JSON array of row IDs, used only by direct audits;
- `evidence_sha256`: digest of the signed verdict or audit bundle.

Arrays in TSV cells are compact canonical JSON, never comma-delimited strings.
Physical line index and raw-line metadata remain parser metadata and never enter
the public row value map.

Legacy rows receive deterministic synthetic IDs from their immutable raw bytes
and physical line. Parsing the same historical ledger on any host yields the
same identities and effective set.

Correction graphs must be acyclic, reference earlier rows, remain within one
board/class/epoch, and reject missing, duplicate, or already consumed credit.

## W2: Direct audit anchoring

A direct audit compares current audited head with the prior direct-audit head for
one board/class using paired measurement, all guards, and the required oracle.
It records the measured ratio as a new score segment and names the active
promotion/span credits since the prior audit in `credit_replaces`.

Effective score is the product of direct-audit segments plus unreplaced active
credits after the newest audit. Prior audit segments are never deleted. At an
audit point, the projected score must equal the product of the audit segments,
independent of the claims that were replaced.

The feed exposes `audited_through`, audit age in commits and time, the current
unaudited tail, and due/overdue state per board/class.

## W3: Automated span audits

Neutral, gate-passing observations enter a per-board/class pending span. A span
becomes due when either:

- the configured number of landed neutral observations is reached; or
- the compounded neutral point estimates cross the configured theta.

The scheduled M5 workflow measures predecessor-before-span against
head-after-span with boosted power, full guards, and oracle parity. `covers`
contains each earlier neutral observation exactly once.

If the span is significant it creates one credit event. If it is statistically
null it consumes the observations and creates no credit. A failing gate consumes
nothing and creates no score input. Promoted, rejected, cross-epoch, cross-class,
or already covered observations cannot be constituents.

## W4: Shrinkage credit

The ledger preserves measured point estimates and confidence intervals. Score
credit uses the directional CI-conservative log shrinkage function:

```text
r < 1: radius = ln(ci_high) - ln(r)
r > 1: radius = ln(r) - ln(ci_low)
r = 1: radius = 0

if CI crosses 1: credited_log = 0
otherwise:        credited_log = sign(ln(r)) * max(0, abs(ln(r)) - lambda * radius)
credited_R = exp(credited_log)
```

Lambda is epoch-pinned. The implementation is a pure function with golden tests,
including the core_metal/wide historical example. A gate-passing direct audit
with `R > 1` remains score-bearing: it records an audited regression rather than
being hidden by a generic rejected outcome label.

## W5: Real resource dimensions

Every measured arm reports this resource vector:

- prove and request time;
- lifetime peak physical footprint;
- process energy delta where the locked host supports it;
- canonical proof bytes;
- availability/source metadata for every counter.

On Darwin, the proving process reads `proc_pid_rusage` for itself using the
documented `RUSAGE_INFO_V6` ABI. This provides lifetime max physical footprint
and energy counters without privileged `powermetrics`. The report records raw
bytes and nanojoules; display conversion happens in consumers. Counter sampling
occurs before warmups and after verified samples, with monotonicity checks.

Unsupported platforms emit an explicit reason for diagnostic runs. A judged M5
run requires non-null, positive, finite counters and fails G5 when they are
missing. Proof bytes come from the exact canonical proof whose digest passes G1.

Each epoch declares per-class RSS and energy regression budgets and a proof-size
budget. G4 reports each failed dimension by name and margin. A faster candidate
whose upper resource ratio exceeds a budget is rejected. The Pareto frontier
uses the complete admitted vector; missing dimensions do not dominate complete
rows and cannot be used to claim a tradeoff.

## W6: Metal calibration

The M5 calibration command runs A/A measurements for every Metal class,
including xlarge and huge, then freezes:

- per-class A/A dispersion;
- per-class anchor prove/request time;
- per-class anchor RSS, energy, and proof bytes;
- runtime identity and AOT bundle digest.

No Metal class uses a generic theta floor once activated. Tight null results are
recorded `neutral`; missing dispersion is a hard G5 failure. Anchor drift is
active for every score-bearing Metal class.

## W7: Peer-relative audit series

The peer runner pins ClementWalter/stwo PR #6 at commit
`07ea1ccca13351028da94e66babf79e7ce91437f`. It runs matched wide-Fibonacci
shapes in an interleaved same-host session and records distinct peer CPU and peer
Metal lanes. It binds repository commit, build features, protocol, workload
geometry, timing scope, warmup/sample policy, host, and proof-equivalence receipt.

The peer series runs at direct-audit cadence. Each point is immutable and linked
to the corresponding direct-audit row. The feed publishes `vs_peer` separately
from `vs_baseline`, including shapes where stwo-zig loses or cannot run. No scalar
Rust result may be relabeled as SIMD or Metal.

## W8: Honest Rust references

Reference evidence contains at least:

- upstream scalar `CpuBackend`, explicitly labeled scalar plus parallel feature;
- upstream `SimdBackend`, explicitly labeled SIMD;
- the pinned Clement peer CPU and Metal implementations.

The scalar and SIMD measurements use the same host/session protocol and matched
workload definitions. Reference JSON includes backend type, feature set, source
commit, executable digest, proof parity result, and method caveats. Feed milestone
text names the backend and never states an unqualified `vs Rust` speedup.

## W9: Judged era and RISC-V activation

The locked `m5-max-stwo-judge` workflow is the only producer of `judged` verdicts.
The always-running required check succeeds for ordinary PRs and fails closed for
an invalid autoresearch submission. Only the GitHub Actions integration may
bypass the protected publication branch, and the activation receipt binds the
exact ruleset, integration ID, bypass actors, workflow digests, manifest digest,
host labels, and release receipt.

At least one existing claimed promotion is rerun with the full guard portfolio.
Its judged row references the claimed row through `supersedes`; effective views
retire the claim but preserve it visibly. Feed output reports judged/effective
row count and judged share by board/class and globally.

The RISC-V group is enabled only after the promoted RF-01 release state, M5
anchors/A/A, pinned Sail/Spike corpus evidence, and activation receipt all
validate. Its promotions remain isolated to the RISC-V board.

## W10: Search health

For each board/class the feed publishes:

- trailing median gradient SNR;
- configured and actual rounds;
- auto-boost reason and target rounds;
- measurement wall hours;
- credited log improvement per measurement hour;
- time series and trailing-window summaries.

Gradient SNR is the absolute credited log effect divided by its directional log
uncertainty. When the configured trailing median is below 2, the runner increases
rounds within the class deadline up to the manifest maximum. It records the
decision before measurement. Round growth is bounded and cannot exceed the
remaining wall-clock deadline.

Measurement hours include both A and B arms, warmups, verification, guards, and
oracle time. Search-health metrics are diagnostic and never alter correctness or
resource gates.

## Workflow and publication gates

Before merge, all of these must pass from a clean integration branch based on the
fully promoted RF commit:

1. Zig format and source-conformance gates.
2. Focused native CPU product tests and report-schema tests.
3. Focused native Metal build/tests and AOT admission checks.
4. Focused RISC-V product/release tests and pinned Sail/Spike evidence binding.
5. All autoresearch unit, hermetic end-to-end, failure-injection, workflow, feed,
   ledger, correction-graph, and activation tests.
6. Synthetic W2-W4 replay: direct audit replaces claimed credit exactly; a
   significant neutral span credits once; a null span credits zero; malformed or
   double-consumed evidence fails closed.
7. Synthetic W5 replay: a faster but over-budget RSS, energy, or proof-size result
   fails G4 and names the dimension.
8. W1 execution on M5: verified log20 x 100 CPU and Metal reports with complete
   admission and resource evidence.
9. W6 calibration on M5 for every active native class, with immutable report
   digests recorded in the epoch.
10. W7/W8 reference measurements on the same M5, with distinct scalar, SIMD,
    peer CPU, and peer Metal identities.
11. A real signed judged rerun that supersedes one claimed row and regenerates a
    deterministic feed showing audit coverage, dimensions, peer series, judged
    share, and search health.
12. Two consecutive feed builds produce identical bytes from identical inputs.
13. The repository pre-push gate passes without modifying frozen epoch-3 files or
    user-owned unrelated work.

## Closure evidence

For the MVP boundary above, workflow gate 9 and the live-authority portion of
gate 11 are discharged by the acceptance contracts in #47 and #48 rather than
by fabricating or locally self-signing authority evidence. The Issue #44 close
comment links those issues alongside the implemented calibration/audit tests;
all other workflow and publication gates remain required for the MVP merge.

Issue #44 may close only after its final comment links:

- the merged commit;
- the new metrics epoch record;
- CPU and Metal log20 x 100 reports;
- per-class M5 anchors and A/A reports;
- direct and span audit fixtures plus the real judged supersession;
- dimensional rejection fixture;
- scalar, SIMD, peer CPU, and peer Metal reference reports;
- generated feed digest and publication check;
- the full gate run.

If any workstream is intentionally rejected, the issue must remain open unless a
recorded design decision explains why its acceptance criterion is obsolete and
names the replacement evidence. Merely deferring a workstream is not completion.
