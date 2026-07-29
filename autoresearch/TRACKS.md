# TRACKS — the autoresearch track partition (campaign v3)

The contract for repartitioning autoresearch from one native-AIR benchmark
suite into frontend×backend tracks, frontend-only tracks, and a
formal-methods track. Supersedes the single-suite framing of the epoch-1/2
campaigns; TASK.md remains the per-session agent brief and must be regenerated
per track as tracks activate. Grounded in three research passes (repo survey,
harness survey, external practice) — provenance notes at the bottom.

## 1. Why the partition

The epoch-1/2 score measured `prove_seconds`, which starts AFTER input
preparation and stops BEFORE encode/verify: the scored quantity is literally
the commitment→composition→FRI→PoW island. VM execution, witness/trace
generation, statement construction, serialization, and verification were
telemetry at best. The Cairo campaigns proved the cost of that blindness:
their biggest wins (fragmented-quotient gather 6.37x stage, bounded-pool
interaction inversion 1.3x whole-proof, 604M committed-cell workloads) are
invisible to every scored workload. The tree already contains the answer —
`src/products/` ships all eight frontend×backend products; the harness boards
never caught up.

## 2. Track taxonomy

A **track = one manifest group owning one board** (the existing 1:1 group→board
mechanism IS the track mechanism; no schema change).

| track (board name) | frontend | backend | product state | disposition |
|---|---|---|---|---|
| `native_cpu` (today `core_cpu`) | Native AIRs | CPU/SIMD | released | **retire-and-complete** (§6) |
| `native_metal` (today `core_metal`) | Native AIRs | Metal | released | **retire-and-complete** (§6) |
| `riscv_cpu` (today `riscv`) | RISC-V | CPU | released | re-score to request boundary, continue |
| `riscv_metal` | RISC-V | Metal | parity_gated | **new track** |
| `cairo_cpu` | Cairo | CPU | released | **new track** |
| `cairo_metal` | Cairo | Metal | parity_gated | **new track** |
| `cairo_frontend` | Cairo | backend-independent | — | **new frontend-only track** (§4) |
| `riscv_frontend` | RISC-V | backend-independent | — | **new frontend-only track** (§4) |
| `formal_refinement` | RISC-V (first) | — | Lean pilot live | **new objective-gate track** (§5) |
| `native_cuda`, `cairo_cuda` | — | CUDA | staged/unavailable | stay staged, fail closed |
| `pr6_supremacy` + per-track supremacy boards | — | — | disabled | objective gates, never scored (§3.4) |

Naming: new tracks use `frontend_backend` names. Existing boards are NOT
renamed — append-only history strands under old names; `core_cpu`/`core_metal`
retire under their historical names (§6) and `riscv` continues under its name
with a widened boundary at its next epoch.

## 3. Scoring the frontend×backend tracks

**3.1 The scored boundary is the PR6 dual boundary, on every track.** The
verified-request boundary (before input/trace/statement construction → after
independent verification) plus the cold-process boundary (before process
creation → after exit, source-JIT included). `prove_ms` is demoted to
diagnostic telemetry everywhere. RISC-V already reports execution/witness
phases fail-closed — its re-scoring is a manifest change. No new track may
ship a laxer boundary than PR6's. (SP1/RISC Zero boundary practice is looser;
this is deliberately stricter — the ZKPoG lesson: kernel-only measurement
missed a 12.7x by ignoring witness generation.)

**3.2 Phase telemetry: named cutpoints, mandatory, never scored.** Per-track
`report_schema` defines execute | witness/trace | commit (LDE+Merkle) |
interaction/LogUp | composition | FRI | serialize | verify. Fail-closed
mechanism telemetry feeds G3 (a submission's predicted phase movement must
appear); scoring a phase invites island optimization — the exact failure this
partition fixes. Dual time units per cell: wall-clock and CPU-seconds, so
parallelism wins and efficiency wins are distinguishable on cpu-vs-metal lanes.

**3.3 Workload baskets.** Each track: scale-classed basket (reusing the
class machinery) + at least two adversarial "killer" workloads
(memory-hole-heavy and builtin-saturating for Cairo; paging-hostile and
Keccak-heavy for RISC-V — the ethproofs killer-block discipline) + the
jittered holdout generator extended from riscv to ALL groups. Cairo's initial
basket: the 7-workload campaign portfolio (all-opcodes 97.4M cells →
memory-7m 604M cells) with fixtures COMMITTED (currently host-local), plus
the orphan `vectors/cairo/cairo_program_matrix.json` corpus (pinned
zksecurity/zkvm-benchmarks with expected cycles) as the acceptance corpus.
Official security parameters only (pow 26 / 70 queries) — no functional-mode
scoring on Cairo. Fast confirmation uses SCALED SHAPES at official params
(never weakened params at full shapes): each class declares a proxy fixture
whose predictive validity is measured and receipted per era (§3.6).

**3.4 Per-track peers and supremacy gates.** Each track gets an optional
`<track>_supremacy` objective board on the PR6 pattern: pinned peer commit +
toolchain (cairo tracks pin upstream `starkware-libs/stwo-cairo`; riscv pins
Stark-V; native keeps ClementWalter/stwo), per-cell dual gates (median ≤0.80,
CI ≤0.90, both ABBA halves), all-cell geomean ≤0.70 that cannot hide a losing
cell, activation only by authenticated judged verdict, and a committed
activation-state file (CUDA `activation_contract` pattern). Objective boards
never write scored rows; they must be added to `ledger.BOARDS` before any
activation or explicitly never write rows (fixing the current pr6 gap).
**The campaign headline is the count of tracks at supremacy** — never a
cross-track blended number (MLPerf's no-aggregation position; per-board
suite scores remain the per-track headline).

**3.5 The confirmation ladder — fast and cheap by construction.** Ranked
truth is expensive (dual boundary, official params, one judge host); the
ladder makes every step BEFORE ranked as cheap as honesty allows, so agents
iterate in seconds and the judge only ever confirms already-evidenced wins.

| tier | cost target | what runs | what it buys |
|---|---|---|---|
| T0 smoke | < 30 s | correctness smoke + ONE stage-profiled sample on the proxy fixture | direction + phase attribution: the claimed phase must move here before anything else is scheduled |
| T1 iterate | < 5 min | paired ABBA on proxy fixtures, sequential early-stop, PoW-excluded boundary | a CI-bearing local estimate; the agent's inner loop |
| T2 claimed | < 45 min | full dual-boundary paired run on the contributor host, real classes, guards impact-mapped | the submission's claimed verdict |
| T3 ranked | judge-scheduled | judged re-run + audits on the designated host | the scored row |

Devices that make the ladder honest AND cheap:
- **Sequential early stopping** (formalizing min/max rounds): a paired run
  stops the moment the CI decisively clears or decisively misses the θ bar
  (group-sequential spending, pre-registered). Large effects — the common
  case under the gain cap, which forces wins to arrive chunked — confirm in
  3 rounds; only borderline effects pay full power.
- **Proxy fixtures with validity receipts**: each class pins a small proxy
  shape (official params, scaled geometry). Per era, the harness measures
  proxy→class predictive correlation on the judge host and commits it as a
  receipt; a proxy whose validity decays below threshold is rotated. T0/T1
  never rank — they gate scheduling.
- **PoW-excluded fast boundary**: pow 26 is ~constant work and pure noise
  for paired deltas; T0/T1 measure request-minus-PoW. T2/T3 keep the full
  boundary — the ranked number never excludes anything.
- **Phase-attribution prefilter**: a submission must name its phase (§3.2)
  and show that phase moving at T0 before T1 runs; a claimed FRI win that
  moves only witness time dies in 30 seconds, not 45 minutes.
- **Warm artifact caches shared across arms**: prebuilt fixtures, cached
  twiddles, authenticated AOT metallibs — builds must never dominate the
  iterate loop; both arms share identical caches so cache state cancels.
- **Judge economy**: T3 admits only T2-verdicts whose CI cleared with
  margin; audits batch per cadence; the M5 spends zero cycles on
  exploration.

**3.6 acceptance:** every tier's cost target is CI-checked per track (a
track whose T1 exceeds 5 minutes must shrink its proxy, not its honesty);
proxy validity receipts are era-frozen like anchors.

**3.5b Anti-gaming set** (mlxfast + SPEC lessons):
- **Per-submission gain cap** per track/class (mlxfast's ~5% acceptance band):
  oversized single-shot wins are distrusted structurally — chunk them.
  Interacts with shrinkage credit: cap the credited ln-ratio, not the record.
- **Benchmark-specials prohibition**: mechanical grep of editable-path diffs
  for workload identifiers/shape constants + G3 generality endorsement
  (SPEC matrix300/libquantum lessons).
- **Gain-concentration monitor**: when one workload dominates a board's epoch
  gains, rotate or retire it at the next epoch boundary.
- **Local-iterate vs ranked separation** (mlxfast): `--guards none` local
  estimates never rank; ranked rows come only from the judge path.

## 4. Frontend-only tracks (cairo_frontend, riscv_frontend)

Optimize compilation, trace generation, and witness layout independent of
proving backend. Editable surface extends to `src/frontends/<f>/**` and
adapter layers (a per-track editable-paths mechanism replaces the single
global list).

**Scored objective: weighted committed trace cells per semantic step**, with
the weight vector regressed each epoch from measured judge-host prover ms per
component (the Sierra-gas discipline: summed weighted resources, never
max-of-resources), frozen for the epoch, refit at boundaries. Jointly
reported anti-gaming pairs: n_steps; per-builtin/opcode counts;
n_memory_holes AND total accessed addresses (hole elimination via dummy
writes shows as address growth); cells-per-step amplification; padding
utilization; for RISC-V, total cycles including paging and continuous cells
(segment counts invite po2 threshold-chasing). New builtins/chiplets enter
the weight vector at measured cell cost before they can score, invocation
counts disclosed.

**Reconciliation gate (G3 for frontends):** a scored frontend win must
predict the measured full-pipeline improvement within stated tolerance on a
sampled backend track — pass/fail row per epoch. Proxy metrics drift; this
closes the loop. Expected effect sizes are small (LLVM pass-tuning for zkVM
guests averaged +1–5%): theta floors set accordingly.

## 5. The formal-methods track (formal_refinement)

Scores **blueprint-DAG node transitions**, not milliseconds and not LOC.
Build the blueprint (Massot Lean-blueprint machinery) over
`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`'s 46-opcode rollout and
SA-1's cross-row obligations. A ledger-equivalent event = one node reaching
`proved` under ALL gates:

- kernel-checked, sorry-free in CI (proof-escape scan already exists);
- `#print axioms` against the pinned allowlist (propext/Quot.sound/
  Classical.choice), machine-enforced;
- **statement immutability**: node statements pinned ex ante like workload
  digests; a statement diff is an identity break requiring review;
- non-vacuity witness per node (the existing negative-controls discipline);
- downstream reachability: node must be a dependency of the pinned top-level
  refinement theorem (mechanical in the DAG);
- spec-side anti-weakening: Sail stays validated by the pinned
  riscv-arch-test corpus.

Node value priced ex ante by statement size (Matichuk: effort ~quadratic in
statement size) and graded by **mutant-killing**: which ledgered forgery
families (malicious-prover harness, proof bit-flip corpora) the theorem now
excludes by proof rather than test — the Certora FV-contest device, and the
repo already owns the mutant corpus. Publish the TCB statement per epoch
(CompCert discipline: proved/validated/trusted partition — Lean kernel,
pinned Sail, extraction path, unverified PCS/FRI wire). Never blended with
performance boards. External alignment: mirror EF Verified-zkEVM's node
taxonomy for legible supremacy claims.

## 6. Retiring the native era ("retire and complete")

The mlxfast contract mechanism, expressed with existing machinery:
`core_cpu` and `core_metal` flip to `promotion_eligible: false` (staged) —
new promotions refuse, history stays fully served (never remove names from
`ledger.BOARDS`: that silently drops history from the feed). The website
renders them as a **completed, frozen contract**: final scores, full ledger,
banked-era banner, "never silently compared with v3 tracks." A final
closing audit run stamps each retired board's last audited score. The native
AIRs continue living as PR6-supremacy objective cells and as guard workloads.

## 7. Per-track epochs ("eras") and the calibration budget

Global epochs are the wrong shape at 6+ tracks (one track's class change
currently resets score compounding for all). Introduce **per-board era**:
`epochs.json` gains per-board epoch sequences; `metrics.py` score_class is
already board-scoped, so the change is contained to epoch bookkeeping,
audit-anchor commits per board, and resource budgets keyed (board, class).
SPEC/MLPerf discipline: scores never compared across eras.

Calibration cost is the real constraint: every track×class needs A/A
dispersion + anchors on the designated judge host (measured actuals: metal
5-class ≈ 87s; riscv 3-class ≈ 15min with one retry; Cairo classes are
minutes-to-hours each at 17–18 GB RSS). One M5 serializes everything
(host-wide judge lock). Budget: activate tracks in waves (§8), add a
matrix/audit cadence per track, and treat additional judge hosts (each with
its own host-local calibration) as the scaling lever. The metal_calibration
module generalizes from its hardwired `BOARD = "core_metal"` to per-board
blocks — required by riscv_metal and cairo_metal.

The ladder (§3.5) is the judge-capacity multiplier: exploration cost lives
on contributor hosts at T0-T2; the M5 confirms, never explores.

**Cross-track agent allocation**: extend `gates_policy.search_health` from
within-board round control to session allocation — reward = CI-cleared
ln-improvement per judge-hour (normalize: huge-class runs cost more), sliding
window (nonstationary payoffs), exploration floor per track so no board
starves (OpenTuner/EXP3 discipline). Per-board notes stay segregated priors
with deliberate periodic technique migration between tracks (island model).

## 8. Activation waves and harness work items

**Wave 1 (opens the campaign):** cairo_cpu + cairo_metal scored tracks
(commit portfolio fixtures; `cairo_proof_v1` report schema + parser; wire the
official-verifier oracle from build gates into the harness; calibrate on M5;
guard portfolio from the campaign regression rows) · riscv re-scored to the
request boundary at its next era · native boards retired-and-completed ·
**website refresh, part 1**: track-explorer shell (one page per track from
feed boards), campaign overview with tracks-at-supremacy headline + score
vector, the native era rendered as the frozen completed contract (final
audited scores, full ledger, banked banner), per-track participate blocks,
phase-telemetry panels, era metadata display. **Wave 2:** riscv_metal (parity-gated product →
scored track) · frontend-only tracks with the weight-vector machinery ·
per-track supremacy boards for cairo (pin upstream stwo-cairo). **Wave 3:**
formal_refinement blueprint + scoring · **website refresh, part 2**: the
formal track's blueprint progress graph + TCB statement, supremacy-gate
state panels, confirmation-ladder status per track (proxy validity
receipts, tier cost health) · CUDA tracks when hardware lands · additional
judge hosts.

Mechanical work items (from the harness survey): extend `ledger.BOARDS`
(never remove); per-group guard registries + per-track impact maps (the flat
native 12-guard portfolio binds to the objective group's binary — nonsense
for cairo/riscv objectives); frontend-aware board auto-routing; per-track
editable paths; report-schema registry entries; per-board era bookkeeping;
resource budgets keyed (board, class); generalized metal calibration;
objective-board BOARDS registration; per-track TASK.md generation; the confirmation ladder: sequential
early-stop in the runner, per-class proxy fixtures + era validity receipts,
PoW-excluded fast boundary flag, T0 phase-prefilter mode in the product
CLIs (`--stage-profile-out` exists on Cairo already), tier cost-target CI
checks.

## 9. Website partition

The site becomes a **track explorer**: one page per track (its suite score,
era, ledger, calibration state, supremacy gate state, phase-telemetry
panels), a campaign overview whose headline is tracks-at-supremacy count +
per-track score vector (never blended), the retired native era rendered as a
completed frozen contract (celebrated, immutable, linked), the formal track
rendered as a blueprint progress graph (nodes by state) + TCB statement, and
per-track participate blocks generated from per-track TASK.md. Feed: boards.*
already maps 1:1 to tracks; additions are per-board era metadata, phase
telemetry summaries, supremacy gate state, and the formal blueprint export.

## 10. Provenance

Repo survey and harness survey (committed evidence in this repo: product
catalog, MANIFEST, metrics/audits machinery, campaign notes, refinement
receipts) + external practice: PR6 gate (in-house), mlxfast-challenge
(contracts, floors, gain caps, local/ranked split), ethproofs (killer
workloads, verified-vs-reported tags), MLPerf/SPEC (no cross-suite
aggregation, era discipline, benchmark-specials bans, matrix300/libquantum),
RISC Zero/Jolt/SP1/EF-zkEVM (phase attribution), Lita (dual time units),
StarkWare Sierra gas (summed weight vectors), ZKPoG (end-to-end necessity),
OpenTuner/EXP3/Hyperband (allocation), Lean blueprint/mathlib port dashboard
/Certora mutation grading/CompCert TCB (formal track), Matichuk et al.
(proof-effort pricing).
