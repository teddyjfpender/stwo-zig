# Scoring boards (v1)

What "the score" means for stwo-zig autoresearch. Seven boards, one promotion
currency. A board defines a basket (which workloads), a lane (which backend
contract), a protocol (how it may be measured), and a display score. The
promotion math never changes per board: a submission is judged by the paired
ratio R of playbook F.1 over its declared basket; boards are baskets, not new
reward functions.

Inherited constraints (normative, from the performance program):

- no single MHz across AIRs — every rate names its native unit;
- cross-workload aggregation is geometric-mean time ratios, never averaged MHz;
- headline numbers come only from `verified_unprofiled` runs;
- backend identity is explicit; fallback counts are part of the result;
- timing scopes are named (prove vs request vs process vs queue).

## Board 1 — Core (the headline)

The "average across sizes" board, constructed so averaging is legitimate.

- **Basket:** the committed native matrix (Wide Fibonacci, XOR, Plonk, state
  machine, Blake, Poseidon at their two checked-in sizes — the 12 rows of the
  current matrix protocol), per lane.
- **Score:** `CoreIndex = geomean_i(prove_i / anchor_prove_i)` over all rows,
  against the frozen pre-optimization anchor. 1.00 = anchor; display as the
  speedup `x(1/CoreIndex)`. The workload-class names and scoring eligibility
  are owned by `MANIFEST.json`, not parser constants; native CPU and Metal
  currently expose small/wide/deep/xlarge/huge while RISC-V remains a separate
  small/wide/deep basket. Sub-indexes use the same construction over a class subset.
- **Why not an average of scores:** a mean of MHz overweights large rows and
  mixes native units; a mean of times is unit-nonsense across AIRs. The ratio
  geomean weights every row equally, is scale-free, and matches the existing
  2%/5% ratio gates.
- **Rules:** one lane per index (no mixing lanes across rows); the site
  headline is the best lane's CoreIndex with the lane named. Anchors are per
  row, frozen once (manifest `anchor_prove_ms` generalizes to per-row values
  at freeze time); a new anchor is a new epoch, never a comparison.

## Board 2 — Kernels (diagnostic, never promotable)

CPU optimization at instruction/kernel scope: S0/S1 of the scope ladder.

- **Basket:** the named hot kernels with pinned inputs and golden vectors:
  four-lane Blake2s compress (parents/s), M31/QM31 batch inversion (elem/s),
  packed FFT butterfly layer (cycles/butterfly), quotient tile execution
  (rows/s), FRI fold2/fold3 (elem/s).
- **Score:** primary observable is **counters, not wall time** — cycles and
  instructions per element (near-zero dispersion), plus achieved bytes/s as a
  **percentage of the measured host roofline** (the STREAM-triad and ALU
  ceilings of F.8 item 1). "% of roofline" is the honest "how much is left"
  number; ns/op is secondary and only with QoS pinned.
- **Hard rule:** kernel results never enter the promotions ledger and never
  aggregate into any other board. The acceptance floor is S3: a kernel 2x
  that moves no proof is recorded and closed (existing precedent). This board
  exists to generate hypotheses and to catch regressions, not to rank
  solvers — scoring it for promotion would invite Amdahl-blind gaming.

## Board 3 — CPU

- **Lane:** `cpu_native`. Basket and score identical to Core, restricted to
  the CPU lane; per-row native MHz (unit named) shown as drill-down.
- **Gate:** zero Metal dispatches in telemetry (trivially true), standard
  G1-G5.

## Board 4 — Metal (resident; zero fallback)

- **Lane:** `metal_resident` — the reserved name. **Eligibility, not just
  scoring:** a row qualifies only when telemetry proves real device dispatch
  AND `cpu_fallbacks == 0` for proving-stage work (host transcript
  observations and orchestration excluded by the architecture contract), and
  for the production class, AOT-admitted pipelines with no source JIT.
- **Score:** same construction as Board 3 once rows qualify. **The board is
  empty today** — the current metal lane performs host Merkle fallbacks and
  therefore belongs to Board 5. Until first entry, the board displays
  progress metrics instead of scores: GPU share of prove time (currently
  13-14%) and fallback count per proof (currently 16 -> 0), neither of which
  is a rankable score.
- **Why strict:** any laxer definition collapses this board into Board 5 and
  destroys the meaning of "Metal beat CPU".

## Board 5 — Hybrid (CPU+Metal)

- **Lane:** `metal_hybrid`, today's Metal lane: best-effort device scheduling
  with counted CPU fallbacks.
- **Score:** same construction as Board 3. **Mandatory context columns:**
  fallback count and GPU-time share render beside every hybrid score so a
  hybrid number can never masquerade as Board 4.
- The site headline "best score" per row = min over Boards 3/4/5 with the
  lane label attached.

## Board 6 — Heavy

Production-shaped and large-geometry work; separate because the measurement
protocol differs, not because the math does.

- **Baskets:** (a) large native geometries (wide rows at log18+, beyond the
  normal committed-cell guard) — cooled, three-sample bounded protocol;
  (b) Cairo programs (the nine-program matrix, Fib tiers first) and SN PIE
  blocks — absolute wall seconds per named workload; (c) the streaming queue
  (S5): sustained proofs/s, p50/p95 latency, retained bytes over the 10- and
  100-block gates.
- **Score:** per-workload absolute time (and proofs/s for streams) with
  **peak RSS and energy as first-class dimensions**, not tie-breakers — the
  17-18 GB Cairo RSS numbers are exactly what this board must keep visible.
  Ratio-to-anchor indexes appear only after a heavy anchor is frozen from the
  first controlled run of each basket.
- **Protocol:** judged heavy runs are scheduled on the labelled, thermally
  controlled machine (conformance-goal rule); they are never casually
  re-runnable, so heavy ledger rows are rarer and marked `heavy_*`.

## Board 7 — RISC-V

- **Lane:** the pinned Stark-V RV32IM adapter, measured in executed
  instructions and scored only against RISC-V workloads and anchors.
- **Isolation:** this board owns one workload group. Its workloads, A/A
  dispersion, anchor budgets, frontier, and promotion HEAD never pool with a
  native board, even when both use the same `small`/`wide`/`deep` class names.
- **Release condition:** the group remains disabled until the AIR, public I/O
  binding, oracle parity, and CLI adapter release gates are complete. Disabled
  means no measurements and no promotions; it never means a silent skip or a
  fabricated score.

## Board 8 — RISC-V × Metal (registered, staged, dark)

TRACKS §2/§8 wave 2. The `riscv_metal` group is registered so the track is
discoverable and so nothing can activate it by accident — not because it can
run.

- **Lane:** the RV32IM frontend on the Metal backend
  (`rv32im-zkvm-v1+lifted-pcs-v1+metal-runtime-v1`), built by
  `zig build riscv-metal-bench`.
- **State:** `enabled: false`, `promotion_eligible: false`. The product is
  `parity_gated`; the installed benchmark prints human-readable output and
  emits no `riscv_proof_v2` report, which the group states in its
  `report_adapter` block (`status: "absent"`). Manifest validation refuses to
  let a group with an absent adapter be enabled or promotion eligible, so the
  three failures — gated product, missing adapter, missing M5 calibration —
  each independently keep the board dark.
- **Board 4 rule applies unchanged.** Before a riscv_metal row can be called a
  Metal result it must prove real device dispatch with zero proving-stage
  `cpu_fallbacks`, which means the adapter must add those counters to the
  RISC-V mechanism contract. Until then the board has no scored classes and
  the feed renders it staged.
- Its name is in `ledger.BOARDS` (append-only) so history can never be
  silently dropped once it does start writing rows.

## Ledger mapping

`promotions.tsv` carries a `board` column. A submission's declared objective
is `(board, workload_class, dimension)`, where the class must be declared and
exposed by that board in the current manifest. The board set is `core_cpu |
core_hybrid | core_metal | heavy_native | heavy_cairo | stream | riscv`.
Kernel results stay out of the ledger by rule; they live in the microharness
diagnostics reports.

For a Metrics v2 epoch, the canonical site headline is the geometric mean of
the manifest-scored classes' effective Metrics v2 ratios. Each class ratio is
computed with directional log-CI shrinkage and direct-audit replacement before
board aggregation; an untouched class contributes 1.0. The board headline
therefore never compounds raw ledger `judged_r` values independently of the
audit engine. The feed publishes the audited-only board geomean beside the
effective headline for provenance.

## Retired boards (TRACKS §6 retire-and-complete)

`core_cpu` and `core_metal` are **retired and complete** as of
2026-07-29. Retirement is expressed with existing machinery and means exactly
three things:

1. The manifest group flips to `promotion_eligible: false` and carries a
   `retirement` block (`retired_at_utc`, `reason`, `closing_audit`). New
   promotions refuse with a retirement-specific message naming the date and
   reason — a retired board is finished, not "not yet live".
2. **History stays fully served.** The board keeps its name in `ledger.BOARDS`
   forever (removing it silently drops its history from the feed), stays
   `enabled` so its workloads keep running as guards and as PR6-supremacy
   objective cells, and keeps its scored classes, ledger rows, suite score, and
   frontier in the feed. The feed publishes retired boards in
   `promotion_scope.retired_boards` and deliberately keeps them OUT of
   `future_boards`, whose contract is "out of scope, never live".
3. The board's era is `banked` in `epochs.json`, freezing its scoring at the
   era it was measured in even after later global epochs open.

The **closing audit** is the one piece of retirement that is not yet recorded.
It runs on the designated M5 judge host through the normal audit controller —
promotion ineligibility does not block it, because auditing is not promoting —
and stamps each retired board's last audited score. Until then
`retirement.closing_audit` is `null`; when the signed bundle lands it becomes
`{completed_utc, bundle_sha256, row_ids}` and the audit cells close.

## Per-track eras and the staged RISC-V boundary switch (TRACKS §3.1, §7)

Each board may own an era sequence in `epochs.json` (`board_eras`; schema and
invariants in schema/ledger.md). An era declares the boundary it scores via
`scored_dimension`:

| value | meaning |
| --- | --- |
| `prove_ms` | today's boundary everywhere: the commitment→composition→FRI→PoW island |
| `request_ms` | the TRACKS §3.1 verified-request boundary — before input/trace/statement construction, after independent verification |

**RISC-V re-scores to the request boundary at its NEXT era.** Era 2 is
unchanged and still scores `prove_ms`; era 3 is deliberately NOT open, because
the switch invalidates the frozen A/A dispersion and needs a fresh judge-host
recalibration at the new boundary. Two gates enforce this:

- `ledger` refuses any era that declares `scored_dimension: "request_ms"`
  without its own measured `aa_dispersion` — a boundary switch never inherits
  calibration;
- the runner refuses to evaluate a board whose era declares a boundary the
  harness does not yet measure, so opening the era before the runner change
  lands fails closed instead of producing prove-boundary rows labelled as
  request-boundary numbers.

The era-3 record template (fill the measured values; invent nothing):

```json
{
  "era": 3,
  "epoch_ref": <global epoch open at the time>,
  "opened_utc": "<UTC of the era open>",
  "reason": "TRACKS §3.1: the RISC-V track re-scores to the verified-request boundary; prove_ms is demoted to diagnostic telemetry",
  "scored_dimension": "request_ms",
  "aa_dispersion": {
    "small": <measured>, "wide": <measured>, "deep": <measured>
  },
  "audit_anchor_commit": "<40-hex commit the first era-3 direct audit chains from>",
  "resource_budgets": {
    "<class>": {"peak_rss_mib": <x>, "energy_j": <x>, "proof_bytes": <x>}
  }
}
```

The manifest side of the switch is the group's optional `scored_dimension`
field (same allowlist, defaulting to `prove_ms`); no group declares a
non-default value today.

### Era 3 also carries the class universe (TRACKS §3.3, §7)

Era 3 is now a **bundled** recalibration: the boundary switch above AND the
RISC-V basket extension open together, so the board pays one A/A dispersion
and one anchor re-measurement instead of two. The extension is staged in
`workload_registry.groups.riscv.era_staged_basket` with
`activates_in_era: 3`. Three properties make era 2 immutable while it sits
there:

1. **Structural.** Staged rows live outside `workloads`. Every execution,
   scoring, holdout-draw, and guard path reads `workloads`, so a staged row is
   unreachable by construction — not merely unselected.
2. **Validated.** `manifest._validate_group_era_staged_basket` refuses any
   staged row id that also exists in `workloads`, refuses a role outside
   `{scored_candidate, killer}`, requires every killer to name its
   `killer_family`, requires at least two killers, and binds the admission
   corpus digest to its committed bytes on every manifest load.
3. **Pinned.** `autoresearch/tests/test_riscv_tracks.py` pins the SHA-256 of
   the riscv group's era-2 scoring universe. Any edit to those 20 rows fails
   until era 3 is actually opened and the pin is moved in the same change.

Nothing about era 2 is re-derived, re-scored, or re-labelled by this staging.

**M5 handoff — the era-3 opening, in order.** Every value below is measured;
none may be invented, and any step that cannot run fails the opening closed.

```sh
# 0. Judge host only, host-wide judge lock held. Build the products.
zig build stwo-zig -Doptimize=ReleaseFast
zig build riscv-trace-dump -Doptimize=ReleaseFast

# 1. Re-verify the staged basket's admission before it can be scored:
#    committed guest/input digests, exact retirement counts, the negative
#    fixture, and a real secure-parameter proof + independent verify per row.
#    A row that does not prove at pow 26 / 70 queries does NOT enter era 3.
zig build riscv-csp-bench -Doptimize=ReleaseFast

# 2. Re-verify the incumbent corpus is unmoved (byte-identical ELFs, trace
#    digests, step counts, final PCs) before anything is re-scored.
python3 scripts/riscv_trace_vectors.py
python3 scripts/riscv_sail_gate.py bind

# 3. Move the staged rows: for each `era_staged_basket.rows` entry whose role
#    is `scored_candidate` and which passed step 1, move it verbatim into
#    `groups.riscv.workloads` and delete it from `rows`. Killer rows stay
#    staged until they are wired as guards (they are never scored). Set
#    `groups.riscv.scored_dimension: "request_ms"` in the same commit, and
#    re-declare the incumbent rows at `--protocol secure` so the class geomean
#    is not a mix of two security levels.

# 4. A/A dispersion per class on the NEW class universe at the NEW boundary.
#    Both changes are in the tree before this runs; a dispersion measured on
#    the old universe is not era-3 calibration.
python3 -m stwo_perf run --aa --board riscv --class small
python3 -m stwo_perf run --aa --board riscv --class wide
python3 -m stwo_perf run --aa --board riscv --class deep

# 5. Anchors per class at the request boundary, same host, same lock.
python3 -m stwo_perf run --anchor --board riscv --class small
python3 -m stwo_perf run --anchor --board riscv --class wide
python3 -m stwo_perf run --anchor --board riscv --class deep

# 6. Append the era-3 record to epochs.json board_eras.boards.riscv using the
#    template above, filling `aa_dispersion` from step 4, `resource_budgets`
#    from step 5, and `audit_anchor_commit` with the commit the first era-3
#    direct audit chains from. `ledger` refuses a request_ms era that carries
#    no measured dispersion of its own, so a copied era-2 value cannot land.

# 7. Update the era-2 universe pin in autoresearch/tests/test_riscv_tracks.py
#    in the SAME commit that opens era 3, and record in the era's `reason`
#    that the basket and the boundary moved together.
```

Until step 6 lands, era 2 stays open, scores `prove_ms` over exactly its 20
functional-parameter rows, and the staged rows score nothing.

## What is deliberately not scored

- No blended CPU+Metal index within one basket (breaks backend identity).
- No kernel aggregate feeding Core (double counting + Amdahl gaming).
- No cross-epoch or cross-anchor comparisons, ever.
- No single-number site score without its lane and basket named beside it.
