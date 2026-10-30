# Endpoint cohorts and a late global-memory bridge

Status: experimental CPU architecture. The clean one-window original has real
4M-instruction canonical-security evidence. A complete block theorem and the
new local-cohort/late-bridge combination remain unqualified.

## Problem and preservation contract

Prove the exact RV32 execution, including program fetch, register state, ordered
RAM effects, precompile relations, halt behavior and final public output. Do not
prove a different guest, silently accept an externally supplied key, replace a
STARK with a host receipt, or aggregate lookup claims drawn under different
challenges. The retained Ethereum execution has 139,214,856 instructions,
57,876,727 real RAM events, 32,835 Keccak calls and 78 recovery calls.

The canonical problem match is an authenticated offline join: independently
prove each partition's local transition chain, commit its boundary records,
then join those committed records under a single globally drawn permutation
challenge. This is not event sampling, approximate deduplication, or a hash-only
attestation. The exact records remain polynomial commitments opened by STARKs.

## Architecture

```text
Pinned ELF + real input
        |
        v
Execute exact contiguous cohorts; collect typed witnesses once
        |
        +---------- parallel local originals ----------+
        |                                             |
        v                                             v
 native execution + register/PC boundary       other cohort, same obligations
 local ordered RAM chain + endpoint AIR
 endpoint range/byte providers + ROM + tables
        |                                             |
        +---- local proof + exact endpoint MAIN root --+
              (23 columns; one record/address/cohort)
                              |
             all first roots and global RAM first roots
                              |
                  freeze one complete late epoch
                              |
              +---------------+----------------+
              |                                |
              v                                v
      narrow bridge batch STARK(s)      sorted global RAM STARK
      reopen SAME endpoint roots       first-value admission + ordering
      four interaction columns/source  range/link/census + final boundary
              |                                |
              +------- same transition z/alpha +
                              |
              recursive verification and exact closure
              local proofs + bridges + global provider
              contiguous PC/register/frame boundaries
                              |
                    one independently verified root
```

Local originals do not carry full intermediate RAM snapshots. Their endpoint
plane under the local epoch remains OPEN. The bridge recomputes only its global
transition plane under the late global epoch; adding the old local-plane sums
would be incorrect. Native execution witnesses and private commitments are not
constructed or committed again. A bounded shared lease retains only the endpoint
main tree, with the original root, coefficients and allocator lifetime.

The bridge component deliberately has one independently derived active-prefix
fixed column, the exact existing 23 main columns, four interaction columns and
one quadratic LogUp recurrence. It does not re-prove the 38 endpoint constraints
or their range providers: accepting its claim requires verification of the local
proof that established those properties for the same root and geometry.

All physical claims are absorbed before interaction commitments. The complete
ordered source roster and global memory first roots precede challenge drawing.
Content-identical endpoint roots can repeat legitimately; source identity,
cohort ordinal and policy still differ. Source ordering is exact, with no dummy
proof jobs or power-of-two proof-count rounding.

The initial bridge implementation supports up to 4,096 source records and batches
of at most 127 sources because its current PCS placement has at most 256 trace
trees. Every batch retains the SAME full epoch and provider roots; the receiver
must cover the full roster exactly once. Separate challenge streams per batch
cannot close a single global memory argument.

## Why the halt guard stays local

A net transition `halt=0 -> halt=0` does not exclude an intermediate write of one
followed by clearing it. The native source therefore proves a narrow per-access
halt guard before endpoint compression. It appends two auxiliary columns to the
native load/store main tree, preserving the exact endpoint-main ABI for the late
bridge. The current whole/local source rejects unsupported caller and terminal
continuations. Caller support needs its own equivalent policy for its full
address representation and an authenticated joint source bus.

## Work, span and evidence

| Change | Evidence | Limit |
| --- | --- | --- |
| Indexed first-touch census | 35.913 -> 2.641 s witness initialization; same original/root bytes | 1.20x full old request, not 13.6x whole prover |
| Clean native endpoint original | 24.989 s production on real 4M instructions, 16.907 GB charged peak | Original only, declared nonterminal window |
| Local originals + late bridge | Production modules and genuine-proof qualification being assembled | No complete-block timing yet |
| Remove RAM clock filler rows | New explicit layout under development | Must replace integer-order checks, not drop them |

At 4M, the complete new original census is 654,891,620 raw M31 cells including
composition, or 1,309,783,240 LDE cells at the selected blowup. Native execution
alone accounts for 216,237,672 main cells including the halt tail and 228,174,936
interaction cells. Thus reducing RAM event count alone cannot produce a 10x
whole-system gain. The first 4M window compresses 1,710,496 RAM events to 505,967
endpoints. Across the complete execution, 4M cohort sets project 57,876,727 RAM
events to 5,444,030 endpoint records; that 10.63x record reduction is a census,
not a measured full-block proving speedup.

The old strong-snapshot recursive diagnostic exposes 3,095,124 byte operands for
257,927 changed memory words at 4M. Repeating this boundary representation per
cohort is specifically what the new architecture avoids. It is not a production
requirement to publicly enumerate every intermediate snapshot change.

Parallel work becomes local-original work per cohort, followed by a shared
first-root barrier, parallel narrow bridge batches/global-memory proving, then
recursive reduction. The critical path includes the slowest cohort and each
reduction level; dividing total work by GPU count alone is not a latency model.
Execution, sorting, initial/final admission and final recursive closure must all
be included in a complete block measurement. Current CPU window observations do
not justify a GPU or full-block timing claim.

## Qualification ladder and falsifiers

1. Fresh local fixed-key verification after all wide producer state is destroyed.
2. Exact endpoint tree identity and geometry across local/bridge proofs; changed
   roots, counts, policy or source ordering must fail receiving admission.
3. Multiple distinct local epochs with one late global epoch; physical claim
   compensation changes the transcript even when an aggregate is unchanged.
4. Global provider verification and equality of its event census/transition sum
   with every bridge batch, including complete ordered batch coverage.
5. CPU PC/register/frame adjacency and externally admitted first/final boundaries.
6. All these checks inside the recursive root, independently rebuilt at receiving.
7. Real increasing Ethereum windows including callers, then fresh initial state,
   actual terminal halt/output and complete block closure.

A benchmark must identify its rung. The existing 4M complete-window original and
small canonical recursive gate do not skip the remaining local/global, caller,
terminal and block publication obligations.


## Qualified CPU measurements at the end of the first eight-hour extension

All real windows below use q70/PoW26, eight CPU workers, real retained Ethereum
ELF execution, 524,288-instruction local cohorts and one late memory epoch.
They are nonterminal windows with an externally pinned incoming state. The
skipped prefix is not proved. `whole` includes execution, witness construction,
source original proving, staging and fresh original-bundle verification.
These rows do not include recursive-root production.

| Window | Cohorts | Global argument | Whole seconds | Local original seconds | Global preparation / proof seconds | Fresh verification seconds | Charged peak GB |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 4,194,304 | 8 | previous packed RAM | 51.689 | 26.835 | 2.223 / 2.796 | 13.416 | 2.935 |
| 4,194,304 | 8 | compact endpoint RAM | 48.066 | 28.236 | 0.374 / 1.014 | 11.394 | 2.933 |
| 8,388,608 | 16 | previous packed RAM | 105.487 | 53.783 | 4.943 / 6.590 | 27.654 | 3.653 |
| 16,777,216 | 32 | compact endpoint RAM | 182.233 | 110.005 | 1.156 / 4.225 | 43.281 | 3.738 |

The 16M run produces 32 local originals, one bridge original and one compact
RAM original. Its 5,436,843 logical RAM accesses reduce to 1,424,595 endpoint
records, retaining 868,375,552 endpoint-tree bytes at peak. The complete benchmark
report, exact executable hash/source manifest, all proof files and verified
artifact hashes are under
`vectors/reports/riscv-cpu-architecture-20261029/native-16777216-local-compact-32x524288/`.
Machine-readable stage data is in `local-global-window-times.csv` beside it.

At 4M, bounded cohorts reduce charged peak from 16.907 GB to 2.933 GB (5.76x).
Compact global preparation is 5.95x faster and its original proof 2.76x faster
than the preceding global argument. The whole 4M bundle gain is about 7%; local
native/ROM work and verification still dominate. These component gains are not
an end-to-end order-of-magnitude claim.

### Closed single-DAG root, separate small-window qualification

`campaign/qualification/new-endpoint-single-dag-q70-parallel4/qualification.json`
records an actual q70/PoW26 STARK over two local original verifier bodies,
one late bridge verifier and one compact global RAM verifier. Its constrained
joins enforce CPU PC/register continuity, exact endpoint-root equality and
physical global-transition closure. No snapshot-delta public ports and no host
closure receipt are used. The window is eight instructions, not the 4M or 16M
workload above.

All ten focused tests pass, including independent admitted-key receiving,
producer-object destruction, strict original-file reload and hostile root,
CPU-boundary and transition mutations. Root size is 987,593 bytes, SHA256
`8865bd8fc37c492862ca52ec473514738140075a076da78871720c9d93a6b50e`.
Four-worker parent proving took 29.285 seconds and complete production 61.456
seconds; this was nonisolated qualification, not a ranked performance run.
An independent eight-worker byte-only receiver took 10.235 seconds and consumed
no original proofs or producer keys. Serial and four-worker producers emitted
exactly the same root bytes.

### Next architectural jump: sparse authenticated ROM

The actual 524,288-instruction cohort used only 146 distinct PCs while the old
ROM provider pads 1,048,576 rows. The new sparse provider retains the full ELF
hash and independently decoded complete program root, but proves selected
public PC/count support in 256 rows (4,096x fewer ROM rows). Canonical standalone
and native-joint q8/q70 originals and strict codecs passed fourteen tests.
A missing used PC is rejected by native-joint lookup closure. These results do
not yet qualify replacing ROM inside the complete local pipeline. A new typed
identity, metadata/codec dispatch and fresh ELF-derived support admission are
required; the old complete-ROM validator must not be weakened.


### Bounded CPU overlap: measured same-proof improvement

The new optional two-job local-proof queue keeps execution/continuation ordered,
then moves each completed native witness and its local providers into one
heap-stable job. Each job owns its CPU pool and mutable proof state. Only the
coordinator publishes files and updates staging/retention budgets. All running
jobs are joined before immutable program/session/budget dependencies are freed,
including error paths. The default remains one proof job.

At 4,194,304 instructions, two eight-worker proof jobs reduce complete original
bundle time from 48.066 to 34.385 seconds (1.40x), with charged peak increasing
from 2.933 to 4.737 GB. All eight local STARKs, the bridge and compact global
STARK are byte-identical to the preceding sequential run. This is a scheduling
improvement under an unchanged theorem, not a new cryptographic benchmark.
Job-duration fields are sums of overlapping jobs and must not be added to obtain
elapsed time; `whole_ns` is the authoritative elapsed measurement. The CSV marks
these rows with `timing_components_overlap=true` and the parallel-job count.

Scaling that single 4M window to 139,214,856 instructions gives about 12.8 minutes
for source execution/preparation/original proving/publication and another 6.3
minutes for original-bundle verification. This is an explicit linear native-only
projection, not a full-block result: it excludes precompile proof work and final
recursive-root production, and the window's instruction mix is unrepresentative
of the complete block. Full-block rates require caller-containing windows and a
closed reduction tree, including proof counts above the current small-DAG limit.


The same two-job schedule also passed the real 16,777,216-instruction window:
135.485 seconds complete versus 182.233 sequential (1.345x), charged peak
5.817 GB versus 3.738 GB. All 34 original proofs are byte-identical between runs.
Fresh verification consumes 44.985 seconds of this request; pre-verification
production/loading/publication consumes about 90.501 seconds. The corresponding
linear native-only block projection is about 18.7 minutes, consistent with the
4M projection; precompile proving and final recursive closure remain excluded.

### Sparse ROM in the actual complete original pipeline

The 4,194,304-instruction sparse-ROM, compact-global, two-job pipeline is now
qualified at q70/PoW26: 23.224 seconds complete, 4.307 GB charged peak. This is
1.48x faster than the same two-job complete-ROM pipeline (34.385 seconds), and
2.07x faster than the original sequential compact-global pipeline (48.066).
Fresh bundle verification falls from 11.304 to 4.736 seconds. Local-provider
preparation falls from 2.659 to 0.800 seconds; local artifact work falls from
1.388 to 0.532 seconds. Total staged bytes fall from 30,036,776 to 16,164,359.
The actual full pipeline independently verifies the selected sparse fixed data,
including ELF binding; the row-count projection is no longer the only evidence.

Local core-proof duration sums change much less, from 19.738 to 18.676 seconds.
Do not attribute the whole result to a universal composition-domain multiplier:
other native/range components still dominate domains. Also, the new protocol
identity changes the deterministic PoW challenges and therefore search work.
These are whole-request measurements across distinct explicit protocol epochs,
not a pure FFT/kernel comparison or a median across repeated runs.

### Large single-DAG root limit: failed experiment, not a published root

The saved complete-ROM 4M/eight-local bundle was passed to the actual one-DAG
root producer. It failed the 48 GB host budget after 253.38 seconds and emitted
no root. Fixed-column compilation took 53.168 seconds, commitment 36.373 seconds,
source witness production 115.849 seconds, and planning 12.196 seconds. Retained
source rows alone occupied 26,422,967,500 bytes before the failed proof stage.
The original bundle remains independently verified. The successful eight-step
recursive fixture must not be cited as evidence that this 4M root completed.

The next root architecture work is bounded/columnar source-witness construction,
release of duplicated retained structures, parallel independent verifier bodies,
and reusable fixed verifier plans separated from per-request admitted values.
Larger trees also need conditional group roots followed by an authenticated final
provider closure; the current finite direct-DAG roster does not itself qualify
266 local proofs for the complete retained block.

### Publication audit

The Python runner had a path-variable shadowing error: after checking all files,
writing the finalized invocation record overwrote the final local `stats.json`.
All proof and statement-metadata bytes and aggregate `report.json` measurements
remain unchanged and match their original hashes. Seven historical observations
retain the overwritten descriptive stats as evidence, with an explicit
`publication-audit.json` and recovered invocation next to each report. Original
lost per-cohort timing bytes are not reconstructed or relabeled. The runner now
uses distinct invocation/artifact paths; a fake-prover end-to-end regression
asserts every artifact still matches its manifest after final publication.

The 16,777,216-instruction sparse-ROM run also passes: 80.865 seconds including
18.255 seconds fresh bundle verification, with 5.107 GB charged peak. This is
1.675x faster than parallel complete ROM (135.485 seconds) and 2.253x faster than
the earlier sequential complete-ROM pipeline (182.233 seconds). The corrected
publisher leaves every artifact byte/hash intact and writes the checked
invocation to its own file. These data remain original-bundle measurements;
no recursive-root or complete-block claim is implied.
