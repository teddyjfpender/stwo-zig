# RISC-V Sail differential CI gate

**Status:** NORMATIVE

**Entrypoint:** `scripts/riscv_sail_gate.py`

**Workflow:** `.github/workflows/riscv-sail-differential.yml`
(required check: `Sail differential gates`)

## Purpose

The pinned Sail model is the only external, non-self-referential definition
of RV32IM correctness this project has; the rigidity harness, the uniqueness
board, and the mutation corpus all compare the system against our own beliefs
about it. Until this gate existed, the strongest Sail evidence was
`conformance/riscv/formal-corpus-evidence.json` — a committed snapshot someone
had to remember to regenerate. For the one oracle that can tell us our
understanding of an instruction is wrong, that was the wrong operational
posture. This gate makes the snapshot mechanically un-stale-able and
re-derives it live in hosted CI with a freshly verified pinned toolchain.

## The decision: scope-blocking PR gate, daily schedule, always-on binding

Three postures were weighed:

1. **Blocking on every PR.** Rejected. A cold toolchain build is tens of
   minutes on a hosted runner, and for changes that cannot alter what the
   attestation means (docs, Metal, core arithmetic — the runner uses no field
   arithmetic) a live run re-compares identical traces and yields zero
   information.
2. **Nightly-only.** Rejected. It lets a semantics-breaking change merge and
   sit wrong on main for up to a day — exactly the window in which the
   sampled AIR-vs-runner harnesses would be testing against a wrong runner,
   converting the external oracle into the self-referential failure this
   project already suffered once with Stark-V.
3. **Cached-toolchain gate, blocking exactly where the attestation's meaning
   can change, plus a daily scheduled live run on main.** Chosen. Warm, the
   toolchain verifies in under a second and the full differential is minutes;
   cold, the toolchain rebuilds from pins inside the same job (measured
   10m07s on an M-series laptop with 8 jobs; hosted cold time is an estimate
   until the first scheduled run, and a red first run is the honest outcome
   if the estimate is wrong).

Two mechanisms make the narrow trigger sound rather than optimistic:

- **Static binding (`bind`, every PR, no toolchain).** The committed evidence
  must describe exactly the committed corpus and pins: identities equal the
  constants that `check_upstream_pins.py` already ties to the ledger, the
  formal profile, and `authority.zig`; program/retirement counts and the
  comparison-field lists match; and the `comparison_digest` recomputes from
  the manifest's per-program trace SHA-256s. It runs in the always-on static
  lane through `scripts/tests/test_riscv_sail_gate.py`, so no fixture or pin
  can move without either regenerated live evidence or a red PR. Binding is
  consistency, not truth — only the live run consults Sail.
- **Digest parity (existing `riscv_cpu` lane).** Runner changes that alter
  behavior on the corpus move trace digests and fail
  `scripts/riscv_trace_vectors.py` until the fixtures are regenerated, which
  itself is a live-trigger path. Runner refactors that keep every digest are
  proven behavior-preserving on the attested corpus, so a live re-run would
  compare the same traces to Sail again. `src/frontends/riscv/{runner,isa}`
  are nonetheless included in the live triggers as belt-and-braces: their
  churn is where semantics live, and a warm live run is cheap.

Live-trigger paths (`LIVE_TRIGGER_PREFIXES` in `scripts/riscv_sail_gate.py`
is authoritative): the corpus fixtures, `conformance/riscv/`, the pin ledger,
the equivalence comparator, the corpus/vector machinery, the toolchain
builder, the gate itself, its workflow, and the runner/ISA sources.

## Fail-closed contract

| Failure | Where it goes red |
| --- | --- |
| Pin drift between ledger, profile, `authority.zig`, comparator constants | `check_upstream_pins.py`, run inside `run` and in the static lane |
| Committed evidence stale against fixtures, pins, counts, or field lists | `bind` (every PR via the static lane, and again inside `run`) |
| Workspace not the pinned sources (wrong revision, dirty, patch drift) | `riscv_formal_tools.py verify`, re-run inside `run` |
| Sail binary whose `--build-info` lacks the pinned model tag or compiler | `verify_sail_binary`, checked twice: toolchain verify and corpus attest |
| Any retirement disagreement, trap-disposition disagreement, or Spike cross-check disagreement | `riscv_trace_vectors.py` live attest — exit 1 |
| Fresh attestation does not re-derive the committed evidence | `run` evidence-drift comparison (only the two build-nondeterministic binary hashes are volatile; identity is source revision + `--build-info`) |
| Toolchain absent or unbuildable | `run` exits 3, printing the exact program/retirement inventory that was **not** checked — never a skip, never green |
| Sail compiler release URL/digest stale after a compiler-version bump | the hash-pinned download plus `resolve_sail_compiler`'s version check |
| Pinned toolchain not functional on the runner — no `z3`, no `dtc`, or a `sail` that will not execute at the pinned version — **on a cache hit as well as a cache miss** | `preflight` exits 3 naming the absent dependency, before the expensive gate; it writes no `toolchain_health` receipt, and the verdict job reads an unwritten receipt as red |
| A live-selected job reporting success with its gate steps skipped, edited away, or never reached | the verdict job requires the `toolchain_health`, `differential_ran`, and `sail_leg` receipts, each written only by the step that did the work; an unselected run has the opposite shape (no job, no receipts) |
| A workspace this run never proved usable being published into the toolchain cache | the save step's `toolchain_state` condition: `verified` or `rebuilt` only. `unavailable`, or an absent receipt because the preflight went red, skips the save |

The scheduled daily run exists for provisioning rot, not semantics: pins
cannot drift by themselves, but caches evict, upstream release assets and
package mirrors decay, and the cold path should be found broken by a
schedule, not by the first PR that needs it.

### Cache hit, cache miss, dependency failure

The cache is a speed input, never an evidence input, and the three paths are
enumerated here because that property is the one a warm cache erodes.

- **Cache miss.** The workspace is cold. `preflight` proves `z3`, the pinned
  `sail`, and `dtc` run on this host, and reports `cache_state=cold`; `run
  --prepare-on-miss` builds the workspace from pins, records
  `toolchain_state=rebuilt`, and the differential runs. The save publishes
  the freshly built workspace.
- **Cache hit.** The restored workspace supplies built Sail/Spike binaries and
  nothing else; the host is still unproven. `preflight` therefore runs anyway
  — this is the whole point of the step — and establishes the same three
  dependencies on this runner. It reports `cache_state=warm`, or `corrupt` if
  the restored workspace does not verify, which is loud but not fatal: `run
  --prepare-on-miss` rebuilds it from pins and the differential still runs.
  Nothing about a cache hit can shorten the path to green. A corrupt entry
  cannot be overwritten under its own key — cache entries are immutable — so
  that rebuild repeats every run until the `-v2-` epoch is bumped: the gate
  stays correct and stops being fast, which is the safe direction and is why
  a workspace is only published once this run proved it usable.
- **Dependency failure.** A provisioning fault — an evicted `z3` mirror, a
  moved Sail release asset, a runner image without `dtc` — is red at
  `preflight` with the dependency named, on both paths. It used to surface
  minutes later as later steps that "did not run", which in a summary line is
  indistinguishable from a gate that was legitimately out of scope. Because
  no `toolchain_health` receipt is written, the verdict job fails the
  required check rather than inheriting a job-level success, and because no
  `toolchain_state` receipt is written either, the failed run does not
  publish its workspace into the immutable cache entry that every later run
  would then restore.

## What this gate does and does not establish

Green means: the exact committed corpus (17 programs, 472,827 retirements,
6 negative dispositions as of this writing) retires identically on this
change's runner and the pinned Sail model, cross-checked by pinned Spike,
and the committed evidence describes precisely that run. It is leg 1 of the
soundness argument — runner ≡ Sail on the corpus. It says nothing about AIR
satisfaction or uniqueness (legs 2 and 3), and corpus equivalence is not
all-input equivalence.

The job additionally runs the Sail leg of the malicious-prover harness with
`STWO_ZIG_REQUIRE_SAIL_ORACLE=1`, because this is the only job with a
verified pinned oracle. Everywhere else that leg reports a visible skip,
which is indistinguishable from a passing check in a summary line; here an
absent oracle is `error.SailOracleUnavailable`, a failure that names the
absence and is deliberately not the disagreement error.

## Known limits, recorded deliberately

- **Hosted cold path is estimated, not yet observed.** Every piece is proven
  (the pinned compiler ships a hash-pinned Linux release binary, dtc/cmake
  are hosted-runner staples, `prepare` builds from pins on this class of
  hardware in ~10 minutes), but the first hosted cold run is the proof. If
  hosted runners cannot build it within the 60-minute budget, the honest
  fallbacks are, in order: a scheduled job that only refreshes the cache, a
  larger runner, or demoting the PR gate to merge-queue/nightly — each of
  which must be recorded here.
- **The required malicious-prover leg adds a cold Zig build to this job.**
  It compiles the RISC-V exhaustive test binary at `-Doptimize=ReleaseSafe`
  with no warm Zig cache (the restored cache holds the formal toolchain
  only), which is minutes on top of the differential and eats into the same
  60-minute budget as the cold toolchain path. If the two together stop
  fitting, the fallbacks in order are: cache the Zig build alongside the
  toolchain, or split the required leg into its own job that restores the
  same workspace — not dropping the requirement, which would return the leg
  to a skip nobody reads.
- **A drifted filter fails the step rather than emptying it.** The required
  leg selects tests with `-Driscv-test-filter="malicious prover"`. The RISC-V
  test runner does report success for an empty selection -- unnamed
  `test { _ = @import(...) }` aggregation blocks are never filtered out, so
  the binary is never actually empty and the exit code alone proves nothing --
  which is why the flag carries `EmptySelectionGuard`
  (`build_support/products/riscv_test_filter.zig`): it compares the executed
  test names against the filter text and fails the build when none match.
  Renaming `src/tests/riscv/malicious_prover_*.zig` therefore turns this step
  red instead of hollowing it out. The guard reports the drift; it does not
  repair it, so the filter still has to be updated with the rename.
- **A forged snapshot passes `bind`.** Binding is arithmetic over committed
  files; only the live run re-derives truth. The live run is triggered by
  every path that could carry such a forgery (the evidence file itself lives
  under `conformance/riscv/`).
- **Local full runs need the workspace.** `python3
  scripts/riscv_formal_tools.py prepare --workspace /tmp/stwo-riscv-formal`
  once, then `python3 scripts/riscv_sail_gate.py run` (optionally
  `--trace-dump-bin zig-out/bin/riscv-trace-dump` to reuse a built dumper;
  digest parity fails loudly if it is stale).

## Relationship to the other gates

`conformance/riscv-pr-proof-gate.md` proves the proof path still produces
and independently verifies artifacts; it deliberately uses the pinned
trace-vector digests so PRs stay fast. This gate is the live half of that
bargain: the digests those lanes trust are themselves re-derived against
Sail whenever their meaning could move, and daily. Strict release execution
uses the same pinned Sail/Spike workspace through
`scripts/riscv_release_gate.py --strict`. The older Stark-V bundle protocol in
`conformance/riscv-release-evidence.md` is archived and has no admission role.
