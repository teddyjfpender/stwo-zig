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

The scheduled daily run exists for provisioning rot, not semantics: pins
cannot drift by themselves, but caches evict, upstream release assets and
package mirrors decay, and the cold path should be found broken by a
schedule, not by the first PR that needs it.

## What this gate does and does not establish

Green means: the exact committed corpus (17 programs, 472,827 retirements,
6 negative dispositions as of this writing) retires identically on this
change's runner and the pinned Sail model, cross-checked by pinned Spike,
and the committed evidence describes precisely that run. It is leg 1 of the
soundness argument — runner ≡ Sail on the corpus. It says nothing about AIR
satisfaction or uniqueness (legs 2 and 3), and corpus equivalence is not
all-input equivalence.

## Known limits, recorded deliberately

- **Hosted cold path is estimated, not yet observed.** Every piece is proven
  (the pinned compiler ships a hash-pinned Linux release binary, dtc/cmake
  are hosted-runner staples, `prepare` builds from pins on this class of
  hardware in ~10 minutes), but the first hosted cold run is the proof. If
  hosted runners cannot build it within the 60-minute budget, the honest
  fallbacks are, in order: a scheduled job that only refreshes the cache, a
  larger runner, or demoting the PR gate to merge-queue/nightly — each of
  which must be recorded here.
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
Sail whenever their meaning could move, and daily. The exhaustive release
protocol (`conformance/riscv-release-evidence.md`) retains its own mandatory
live comparison; nothing here weakens it.
