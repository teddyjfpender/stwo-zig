# Site feed schema (v4) — the repo ↔ website contract

`stwo-perf feed` compiles every checked-in evidence source into one JSON
file: `autoresearch/site/feed.json`. The website renders feeds and nothing
else — GitHub files are the source of truth, and this schema is the entire
contract. It is project-generic: any future autoresearch project publishes
the same shape from its own harness.

Guarantees a producer must uphold (all testable):

1. **Committed inputs only.** The feed is a pure function of files in the
   repository. The producer refuses to run when any input path has
   uncommitted changes (`--allow-dirty` exists for local debugging only and
   stamps `provenance.dirty_inputs`; a dirty feed must never be published).
2. **Deterministic.** Same inputs → byte-identical output (sorted keys; the
   only timestamps are sourced from the inputs or the commit itself, never
   from the wall clock).
3. **Provenance-bound.** `provenance.inputs_sha256` digests every input that
   feeds numeric content — manifest, ledger, epochs, the history index, and
   the exact matrix report rendered (verified against the digest the index
   records for it). Note titles are display-only and not digested.
4. **Nothing invented.** Empty boards render empty; missing telemetry is
   omitted, never zero-filled.

**The one-commit lag, by construction:** a feed committed into the repo
names the commit it was generated FROM — necessarily the parent of the
commit that adds the feed, since committing the feed advances HEAD.
Verification therefore means "`inputs_sha256` matches the input files", not
"`repo_commit` equals the commit containing the feed". CI regeneration
gates must compare feeds with the `provenance.repo_commit*` fields
excluded, or regenerate at the recorded commit.

Top-level keys:

| key | contents |
| --- | --- |
| `feed_schema_version` | integer; consumers read per version |
| `project` | slug, display name, harness name, contract pointer |
| `provenance` | repo commit + commit time, input digests, determinism note |
| `anchor` | frozen flag, anchor commit, per-class anchor prove-ms |
| `epoch` | current global measurement epoch: `number`, `opened_utc`, `reason`, and A/A dispersion (theta inputs). v4 adds `opened_utc`/`reason` |
| `promotion_scope` | v2: the decided benchmark set — manifest class registry (scored, resource, timeout, and sampling policy), workload groups (board, enabled, disabled_reason, `promotion_blocked_reason`, `retirement`, per-workload class + native unit), `owned_boards`, `staged_boards`, `retired_boards`, `future_boards`, and committed baseline directories. A board in `future_boards` exists only as scoring universe; consumers render it as out-of-scope, never as empty-but-live. **A retired board is never in `future_boards`** — see `retired_boards` below |
| `boards` | per scoring board (schema/scoring.md): ledger entries, manifest-owned `scored_classes`, that board's **own current era** (`era`), `retirement`, `phase_telemetry`, canonical Metrics-v2 `suite_score` for its era's epoch, and per-class frontier. `suite_score` exposes effective and audited class ratios, their board geomeans, active credit-event counts, index, and speedup; it is aggregated after shrinkage and audit replacement, never from raw `judged_r`. Each live class also exposes its Metrics-v2 `audit` projection: effective/audited score, `audited_through`, deterministic commit/time age, unaudited tail, due/overdue state, span coverage, and claimed-versus-judged evidence share |
| `search_health` | v3: manifest policy plus per board/class availability, trailing summary, latest configured/actual rounds and boost decision, complete-wall measurement hours, credited log-improvement/hour, immutable time series, and trailing decay series; classes come from the manifest and historical rows, not a fixed feed list |
| `metal_resident_progress` | Board-4 progress metrics while the board is empty (fallbacks/proof, zero-fallback row count) |
| `latest_matrix` | the newest benchmark-history matrix run: per-row workload identity, headline eligibility, proof parity, and per-lane medians (prove ms, native MHz with its unit, request ms, peak RSS, fallback/dispatch counts). v4 adds per-lane `backend` (verbatim backend identity from the committed report) and `board` (the scoring board that identity belongs to). New matrix lanes also retain the optional `request_resources` governed measurement vector verbatim; historical lanes omit it rather than fabricating zeros |
| `baseline_matrix` | the EARLIEST committed matrix run, same shape as `latest_matrix`: the fixed pre-optimization reference vector. Suite-level progress is the vector of per-workload time ratios (latest/baseline, paired by workload name, headline-eligible rows) aggregated by geometric mean — the only consistent mean for normalized ratios — with the worst component reported alongside so no single coordinate can be gamed |
| `references` | committed external reference measurements from `autoresearch/reference/*.json`, plus immutable `peer-series/runs/*.json` audit points. `peer_rust_scalar` and `peer_rust_simd` are distinct backend-typed references; consumers MUST name the backend and render timing caveats. `peer_relative_series` defines the exact PR #6 wide-Fibonacci series, while discovered `peer_series_run_*` entries carry same-host four-lane points and proof-equivalence receipts. An empty series is uncalibrated, never parity. |
| `history` | run index (ids, kinds, report digests) and comparison count |
| `submissions` | id, note title, outcome (or `pending`), judged R, `verdict_kind`, `workload_class`, `solver` (landing-commit author; GitHub noreply emails yield the exact login), full public `note` text, and digest-bound `transcripts` refs (label, sha256, captured_by, short leading excerpt) |
| `notes_count` | standalone note count |

Consumer rules: never upgrade a `claimed`/`pending` state to judged; always
display a lane and native unit beside a number; treat feeds from forks as
untrusted until `provenance` digests are verified against the repository.

Version history: v1 had no `promotion_scope`; v2 added it; v3 adds
`search_health`; v4 adds per-board eras, retirement, phase telemetry, matrix
lane board attribution, and `epoch.opened_utc`/`epoch.reason`. Consumers use
`promotion_scope.owned_boards` to decide which boards accept new promotions and
`promotion_scope.retired_boards` to decide which are completed contracts.
Search-health points with `available=false` remain part of the time series and
must render their `unavailable_reason`, never a fabricated zero. Malformed or
missing evidence on a v3 `judged` row prevents feed publication; legacy v1/v2
rows remain readable and explicitly unavailable.

## v4: per-board era metadata (TRACKS §7, §9)

Every entry in `boards` carries an `era` object. It is always present and every
key is always set:

| field | meaning |
| --- | --- |
| `number` | the board's era number (1-based, per board) |
| `epoch` | the global epoch the era inherits — the epoch its `suite_score` is computed in |
| `opened_utc` | when the era opened |
| `reason` | why it opened |
| `status` | `open` or `banked` |
| `banked` | `status == "banked"`; **the retired/frozen flag** |
| `closed_utc` | when a banked era closed, else null |
| `scored_dimension` | the boundary the era scores (`prove_ms` today; `request_ms` is the TRACKS §3.1 verified-request boundary) |
| `note` | free-form operator note, or null |
| `source` | `board_era` when the board owns an era sequence, `global_epoch` when it falls back |

A board that declares no era sequence falls back to the newest global epoch and
reports `source: "global_epoch"` — the fallback is explicit, so consumers no
longer have to infer an era from the suite-score epoch. **Scores are never
compared across eras**, exactly as they are never compared across epochs; a
banked era's numbers are final.

`boards.<board>.retirement` is the TRACKS §6 block (`retired_at_utc`, `reason`,
`closing_audit`) or null. A retired board renders as a **completed, frozen
contract**: final scores, full ledger, banked-era banner, never silently
compared with live tracks. Its history is served exactly as before — it keeps
its ledger entries, scored classes, suite score, and frontier. `closing_audit`
is null until the judge host records the final audit that stamps the board's
last audited score, then becomes `{completed_utc, bundle_sha256, row_ids}`.

## v4: phase telemetry (TRACKS §3.2)

`boards.<board>.phase_telemetry` publishes the named phase cutpoints for a
board, or **null when no committed artifact carries them**. Phase telemetry is
mandatory diagnostic evidence and is never scored; an absent board means "not
yet measured on committed evidence" and must render as an honest absence, never
as zeros.

Source contract: the producer reads committed JSON documents from
`autoresearch/reference/phase-telemetry/*.json` only — never a local run, never
a derived estimate. Each document declares `board` (a registered scoring
board), `report_schema`, `measurement_boundary`, `phase_profile_source`, and
`phase_seconds`, and may declare `run_id`, `workload`, `workload_class`, and
`mechanism`. Every file is digested into `provenance.inputs_sha256`, and a
malformed document fails the feed rather than reaching a consumer. Published
shape:

```json
{
  "report_schema": "cairo_proof_v1",
  "run_id": "…", "workload": "…", "workload_class": "…",
  "measurement_boundary": "cold_process",
  "phase_profile_source": {"invocation_index": 4, "scored": false, "note": "…"},
  "mechanism": {…},
  "stages": {"phase_seconds": {"execute": 1.0, "witness": 2.0, "…": null}}
}
```

A `phase_seconds` cutpoint may be `null` — a documented, explicitly unmeasured
phase (e.g. Cairo's `serialize`, which happens outside the stage recorder). No
board publishes phase telemetry at the time this schema version lands: the
export machinery and its source contract are live, and the drop point is empty.

Audit age is computed from committed Git timestamps and ancestry, never the feed
producer's wall clock. A fork or generic consumer missing the audit commit
publishes an explicit unavailable reason and null age, never an invented zero.
A class with no evidence publishes null coverage/share ratios, not synthetic
percentages.

Transport: the same document is served identically from the committed file
(`autoresearch/site/feed.json`, e.g. via GitHub raw) and from a running
project backend at `GET /v1/feed`. Consumers cache a fetched feed and treat it
as current until `provenance.inputs_sha256` differs — the digest set is the
supersession key, not timestamps or HTTP headers.
