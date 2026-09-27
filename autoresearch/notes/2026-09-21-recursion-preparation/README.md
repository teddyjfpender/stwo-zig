# Recursive preparation improvements — 2026-09-21

Local advisory research following the autoresearch problem-match and measured
confirmation pattern. The recursive-parent endpoint is not a scored board;
no judged verdict or promotions-ledger entry is claimed.

## Confirmed Metal parent result

Three fresh-process ABBA rounds on the final rebuilt binary, after one discarded
warmup per arm, using rebuilt
baseline and candidate binaries on the same host. No builds ran during these
confirmation samples. All 14 outputs independently verified after producer exit,
without native inputs, and matched the qualified key, claim and proof hashes.

| Complete-parent measurement | Baseline | Candidate |
| --- | ---: | ---: |
| Median process seconds | 7.062 | 5.572 |
| Median maximum RSS bytes | 4,392,460,288 | 4,392,337,408 |
| PCS authority seconds | 1.058 | 0.938 |
| PCS row construction seconds | 0.887 | 0.651 |
| Tuple projection seconds | 1.328 | 0.868 |
| Typed interaction generation seconds | 0.419 | 0.172 |

Hodges–Lehmann candidate/baseline ratio: 0.78979; seeded 95% bootstrap interval
[0.78714, 0.79112], over three ABBA round ratios. Estimated speedup: **1.266x**.
This is about 21% less complete-parent elapsed time. Three rounds are a small
local sample, not cross-hardware or production-scale qualification.
Stage rows are diagnostic; nested phases must not be summed with their parents.

## Confirmed CPU parent result

Three fresh-process ABBA rounds plus one discarded warmup per arm: median
10.293 to 9.062 s. Candidate/baseline estimate 0.87858, 95% bootstrap interval
[0.87646, 0.88044], speedup **1.138x**. All 14 proofs independently verified and
matched the same qualified artifacts. This confirms the shared host changes on
both backends; the Metal-only interaction path is not needed for the CPU gain.

## Complete eight-segment Metal product

A fresh single baseline/candidate comparison rebuilt both leaf and parent
producers and used the same admitted eight-segment, 16-address program:

| Production boundary | Baseline seconds | Candidate seconds |
| --- | ---: | ---: |
| Native plus recursive leaves | 65.311 | 61.774 |
| All seven recursive parents | 51.321 | 40.360 |
| Total production | **116.632** | **102.134** |
| Complete gate, including verification/rejection cases | 127.691 | 112.542 |

This is an observed 1.142x total-production ratio (12.4% less time), **one pair,
not a statistical full-tree speedup claim**. Each arm passed 300 acceptance and
rejection checks; all 45 key/claim/proof artifacts match qualification. Required
native, leaf and parent GPU interaction dispatch coverage passed. Every parent
was verified after producer exit. An additional 30 independent statement
substitution checks passed on the candidate tree. The candidate tree uses newly generated leaves
and intermediate parents, rather than replaying only the archived final node.

## Changes and experiments

1. PCS and FRI input owners now validate the complete authority/witness once and
   directly allocate selected-lane logical rows. The previous full-column path
   remains a test oracle. No per-row rehashing or unchecked admission is added.
2. Exact tuple aggregation packs up to seven base-field values plus arity into
   a complete 32-byte key. A separate namespace retains SHA keys for long and
   extension-field tuples. Hash-table collisions still compare complete keys.
   Domain separation, range validation, signed weights and sticky failures remain.
3. Column materialization uses physical tiles of 32 rows and the inverse of the
   existing committed permutation, keeping destination writes contiguous.
4. Small structural hash integer-encoding helpers are inlined where the stack
   sample identified call overhead. Canonical hash streams are unchanged.

The selected-lane exploratory run moved the row phase from 0.881 to 0.676 s,
while unrelated test compilation was active. Its total-time ratio is deliberately
not a confirmation claim. The uncontended two-round packed-key checkpoint moved
complete-parent medians from 6.858 to 6.215 s; it is an intermediate diagnostic,
not a CI-backed promotion. A separate four-round combined run measured 6.891 to 5.468 s (1.259x),
95% ratio interval [0.7909, 0.7977]. The final binary was then rebuilt after a
test-only fixture typing fix and separately confirmed in the three-round run
above. Both measurements are retained; only the latter times the exact final
binary used for complete-tree qualification.

## Validation and scope

Ten focused ledger/layout tests pass: canonical ledger parity, arity boundaries,
domain/extension separation, cancellation, allocation failure, provider phases,
streamed projection and committed-permutation/padding parity. The genuine child
ownership test passes with its intended one-address fixture and same-shape
independent alternative statement. It includes both-lane PCS differential checks,
logical AIR checks and malformed proof/claim/input rejection.

Source conformance retains the same 103 baseline failures, with no new failure
categories; changed Zig formatting and diff whitespace checks pass.

Two fixture setup failures are retained: the larger fixture does not match the
boundary test's fixed one-address profile; a different segment's statement had a
different shape. Neither required weakening the test or implementation. Both-lane
PCS parity also passed on the larger fixture before its unrelated boundary check.

Parameters remain development recursive_q193_v1: 193 queries, 16 PoW bits,
log blowup 1 and fold step 4. No circuit, key, proof format or soundness parameter
changed. This is not CSP's 70-query/26-bit profile or production-security qualification.

## Total-tree target and next research boundary

The newly measured baseline decomposes 116.632 s into 65.311 s of leaf
production and 51.321 s summed parent production. Eliminating parent time
alone cannot yield 10x on that fixture. Its 482 instructions and 16 memory
addresses are not a representative large-program scaling study.

Tenfold total improvement remains unmet. The next structural experiment should
reduce PCS/DEEP intermediate inputs and arithmetic-wire rows in both recursive
leaves and parents. Existing four-term accumulation and QM31 multiply-add already
provide fusion; larger blocks require new authenticated AIR/key/backend artifacts
and independent soundness checks, not simply a faster host opcode. Measure padded
committed columns, provider events, total time and memory against this unchanged
baseline. Keep proof-identical host optimizations separate from circuit redesign.

## Reproduction and evidence

Baseline source is commit `1c6c81ecf98813ca3c91988888d9f2af6474763e` (the PR #198
head merged into main). `evidence/candidate-source.patch` and its file-hash map
identify the changes. Binaries are ReleaseSafe; build logs, stack sample, raw
phase logs, binary hashes, verifier receipts and ABBA samples are retained.
Temporary proof bundles are not checked in; their hashes match the existing
qualified artifacts, and the admitted tree can regenerate the pinned children.

Use [parent_pair.py](../../benchmarks/recursion/parent_pair.py) with `--receipt`,
`--baseline`, `--candidate`, a new `--output`, and `--rounds 4`. Build both arms
first, and run without concurrent compilation. It records full process time and
RSS, discards warmups, independently verifies every proof, checks qualified
artifact identity, and uses the existing autoresearch statistics implementation.

Problem matches:
- [Selective materialization](../20260921-132154-recursion-selective-materialization-problem-match.md)
- [Exact tuple keys](../20260921-132420-recursion-exact-tuple-aggregation-problem-match.md)
- [Blocked columns](../20260921-133011-recursion-blocked-column-materialization-problem-match.md)
