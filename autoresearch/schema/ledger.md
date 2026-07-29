# Promotions ledger schema (v1-v3 rows)

`autoresearch/ledger/promotions.tsv` is append-only. CI rejects any PR that
edits or reorders existing rows, and a correction is a new row whose
`supersedes` names the corrected one. Because the file is append-only, the
header is frozen at the v1 column list forever; later schema versions extend
**rows** (extra trailing cells), never the header — every row is read per its
own `schema_version`.

Two writers append: the promote workflow (the judge identity) writes
`verdict_kind=judged` rows from HMAC-verified judged verdicts, and the
maintainer's local `stwo-perf promote-claimed` writes `verdict_kind=claimed`
rows — optimistic adjudication of a merged submission's claimed verdict,
recorded during the pre-judge era. A claimed row is never silently upgraded:
when the judge host activates, the judged re-run appends a new row whose
`supersedes` names the claimed one, and consumers must always display the
kind they were given (site-feed contract: never upgrade claimed to judged).

Columns (tab-separated; v1 columns first, one submission per row):

| column | meaning |
| --- | --- |
| schema_version | integer; rows are read per their own version |
| harness_commit | autoresearch/ tree hash the judge ran |
| epoch | measurement epoch (ledger/epochs.json); ratios never compare across epochs |
| judged_at_utc | ISO-8601 UTC of the judged run |
| commit | promoted repository commit |
| scope | acceptance rung (s3..s5) |
| board | scoring board (schema/scoring.md): core_cpu / core_hybrid / core_metal / heavy_native / heavy_cairo / stream / riscv |
| workload_class | manifest-declared class exposed by the row's board (currently small / wide / deep / xlarge / huge for native CPU and Metal; RISC-V remains small / wide / deep) |
| outcome | `promoted` / `neutral` / `rejected` — only promoted rows shape the frontier |
| judged_r | geometric-mean paired ratio (<1 improves) |
| ci_low / ci_high | 95% bootstrap CI of judged_r |
| prove_ms / native_mhz / peak_rss_mib | candidate portfolio geometric means on the declared class. v3 writers populate peak RSS from `score.resource_portfolio`; `0.0` is retained only as the unavailable sentinel for verdicts that predate that evidence block |
| waits / dispatches | Metal telemetry when applicable, else empty |
| energy_j | candidate portfolio geometric-mean joules per proof from `score.resource_portfolio`, else empty |
| gates | `G1..G5:pass` or the failing gate list (a failing row records a rejection) |
| holdout | `pass`/`fail` plus the generator seed, e.g. `pass;seed=180734` |
| submission_id | submissions/<dir> name |
| predecessor | the paired A-arm commit |
| supersedes | empty, or the judged_at_utc+commit of the row this corrects |
| verdict_kind | **v2 only** (24th cell): `judged` (signed judge verdict) or `claimed` (maintainer-adjudicated optimistic row). v1 rows are read as `judged` — only the judge ever wrote them |
| row_id | **v3**: `sha256:<hex>` of the canonical v3 row payload excluding this cell; immutable physical identity |
| observation_id | **v3**: stable digest of `(submission_id, board, workload_class)`; corrections retain it |
| evidence_kind | **v3**: `promotion`, `span_audit`, or `direct_audit` |
| covers | **v3**: canonical compact JSON array. Non-empty only for a span audit, naming earlier gate-passing neutral promotion observations in ledger order |
| credit_replaces | **v3**: canonical compact JSON array. Non-empty only for a direct audit and exactly equal to the active, non-audit credit-event IDs since the previous direct audit |
| evidence_sha256 | **v3**: digest of the canonical signed/claimed verdict payload that produced the row |
| proof_bytes | **v3**: positive integer candidate proof size for the deterministic class portfolio |
| measurement_seconds | **v3**: positive finite wall seconds spent collecting this evidence; canonical six-decimal cell |
| measurement_rounds | **v3**: positive integer total paired portfolio rounds |

v1/v2 physical IDs are synthesized as a digest of a domain separator, their
immutable physical index, and their exact existing row bytes. This changes no
ledger byte and is stable under every append. Legacy correction keys are
resolved only inside the same epoch/board/class, avoiding the historical
collision where several cells shared one `judged_at_utc+commit` key.

## Metrics v2 invariants

- Corrections point to an earlier physical row, preserve observation, epoch,
  board, and class, and replace only the active tip of that correction chain.
- Span coverage is chronological and disjoint. A span consumes only neutral,
  gate-passing promotion observations; a neutral span consumes the span but
  contributes no score credit.
- A direct audit is score-bearing whenever its gates pass, including a
  regression whose generic promotion outcome is `rejected`. Its replacement
  list is the exact current non-audit credit set; missing or surplus IDs fail.
- Promotion and span credit uses directional neutralward log-CI shrinkage. A
  CI crossing 1 receives zero credit. Direct audits use their point estimate.
- At every direct audit the class score equals the chained direct-audit
  product exactly. Later shrunken credits accumulate only until the next audit.
- The first direct audit in an epoch names that epoch's canonical 40-hex
  `metrics_v2.audit_anchor_commit` as predecessor; later audits name the prior
  audit's candidate commit. Empty replacement credit never bypasses this chain.
- A Metrics v2 epoch pins an exact positive finite `peak_rss_mib`, `energy_j`,
  and `proof_bytes` upper-ratio budget for every scored class. Evaluation
  resolves this vector from the epoch; missing classes, dimensions, or values
  fail closed before measurement can produce a score-bearing verdict.

A direct-audit segment attributes the complete `predecessor..candidate` change
to the one audited board/class. It does not apportion the measured ratio among
commits in that interval; cross-class commits in the span are therefore assumed
performance-neutral for this cell when interpreting attribution.

Corrections replay through later audits. If `supersedes` replaces a promotion
whose row ID was already consumed by a direct audit, that audit's recorded
`credit_replaces` is no longer the exact active set and the class score fails
closed. Correcting the promotion alone cannot rewrite a banked audit segment;
the dependent audit row must also be superseded with evidence that replays the
corrected history.

The Pareto frontier and anchor-drift budgets are computed from this file by
`stwo-perf frontier`; nothing else is authoritative.

## Per-board eras (TRACKS §7)

Global epochs are the wrong shape at 6+ tracks: one track's class change resets
score compounding for all of them. `ledger/epochs.json` therefore carries an
optional `board_eras` block beside the global `epochs` list.

```json
"board_eras": {
  "note": "…why this block exists…",
  "boards": {
    "<board>": [
      {
        "era": 1,
        "epoch_ref": 2,
        "opened_utc": "2026-07-21T16:00:00Z",
        "reason": "…why this era opened…",
        "status": "open" | "banked",
        "closed_utc": "2026-07-29T00:00:00Z",
        "audit_anchor_commit": "<40-hex>",
        "aa_dispersion": {"<class>": 0.0123, "<class>": null},
        "resource_budgets": {
          "<class>": {"peak_rss_mib": 1.05, "energy_j": 1.05, "proof_bytes": 1.0}
        },
        "scored_dimension": "prove_ms" | "request_ms",
        "note": "…free-form operator note…"
      }
    ]
  }
}
```

`era`, `epoch_ref`, `opened_utc`, and `reason` are required; everything else is
optional and defaults to inheritance. **The global epochs remain the fallback
and are never rewritten**: a board absent from `boards` resolves to the newest
global epoch exactly as it did before eras existed, and every ledger row
referencing epoch 1 or 2 keeps parsing, scoring, and rendering unchanged. The
`epoch` ledger column still names a **global** epoch — an era is a per-board
*view* of one, never a competing numbering.

Resolution API (`stwo_perf.ledger`):

| function | behaviour |
| --- | --- |
| `board_eras(root, board)` | validated raw era sequence, `()` when none |
| `current_era(root, board)` | newest era as a normalized view, or `None` |
| `epoch_for_board(root, epoch, board)` | one named epoch resolved for a board |
| `current_epoch(root, board=None)` | `board=None` is byte-for-byte the old behaviour |
| `aa_dispersion(root, board, class)` | board-scoped, era override merged per class |
| `resource_budgets(root, class, board=None)` | TRACKS §8 (board, class) key with class-only fallback |
| `scored_dimension(root, board)` | the era's scored boundary; `prove_ms` by default |

Invariants, all fail-closed:

- A board named in `boards` must be in `ledger.BOARDS`; an unregistered name is
  an error, never a silently ignored entry.
- Eras are numbered `1..n` contiguously; `opened_utc` strictly increases;
  `epoch_ref` never decreases and must name a declared global epoch.
- An era may not open before the global epoch it inherits.
- At most one era is `open`, and it must be the newest. Every other era is
  `banked` with a `closed_utc` that does not fall after the next era opens.
- **A banked newest era pins its board.** When a later global epoch opens, a
  board whose newest era is banked stays on its own era — that is precisely
  what retiring a board means (TRACKS §6): history keeps being served and the
  frozen score never drifts onto a universe it was not measured in.
- Overrides are merged, not substituted: a class the era does not pin inherits
  the epoch's dispersion or budget. `audit_anchor_commit` is per board with the
  epoch's anchor as fallback, so `metrics.policy_from_epoch` on a
  board-effective specification yields that board's anchor and carries the
  `board`/`era` identity as provenance.
- An era declaring a `scored_dimension` other than `prove_ms` MUST declare its
  own measured `aa_dispersion`: a boundary switch invalidates inherited
  calibration and may never reuse it (TRACKS §3.1/§7). The runner additionally
  refuses to evaluate any board whose era declares a boundary the harness does
  not yet measure, so a declared-but-unimplemented boundary cannot produce a
  mislabelled score.

Scores are never compared across eras, exactly as they are never compared
across epochs.

## Audit production protocol

`python3 -m stwo_perf.audits plan` is the deterministic W2/W3 controller. It
binds its plan to the exact manifest, epoch, ledger bytes, and candidate HEAD,
then emits due board/class cells in manifest order. Direct audits take priority
when both cadences are due. Every runnable item fixes the exact predecessor,
candidate, span coverage or direct replacement set, `scope=s5`, judged mode,
the full regression portfolio, the pinned final oracle, and bounded boosted
measurement power. There is no `guards_mode=none` audit path.

The scheduled/manual `autoresearch-audit` workflow executes at most the
requested number of items sequentially on the designated M5 judge. The
self-hosted job receives no signing secret. A hosted signing job checks out the
same immutable candidate, recomputes due state from authority, validates every
guard/oracle/power binding, signs the verdict, and materializes the exact v3
row. Signed bundles are retained on `audit-verdicts` and can be ingested with
`python3 -m stwo_perf.audits append`.

Append fails closed if HEAD, manifest, epoch, or any ledger byte changed after
planning. It verifies every signature and row encoding, parses the complete
prospective ledger, and replays the affected Metrics-v2 score cells before one
write. A failed span keeps `covers` for diagnosis but consumes nothing. A
failed direct audit has an empty `credit_replaces`, so it cannot retire credit.
Null, gate-passing spans consume their observations once with zero score input.

The canonical board suite score takes the geometric mean of the current
epoch's effective Metrics v2 class scores over that board's manifest-declared
`scored` classes. This happens after shrinkage and audit replacement; it never
re-compounds raw `judged_r`. Untouched classes contribute identity. Changing
the scored class universe requires a new epoch so historical rows cannot
dilute or rewrite the new score.
