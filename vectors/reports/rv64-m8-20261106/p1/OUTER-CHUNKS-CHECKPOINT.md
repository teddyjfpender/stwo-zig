# Bounded outer composition: headline failure remains

**P1 remains incomplete.** The source-bound companion module evaluates the
unchanged original roots in groups using a 32-column full-domain cache.
The small block passes cold/warm payload and capture-SHA256 identity, with
all four fresh CPU accepts [M]. The headline attempt completes five services,
then the sixth service fails during its cold request. It has no completed
3+3 comparison and no final candidate median.

| 24628607, two RTX 5090s | Default | Composed candidate |
|---|---|---|
| Completed warm request observations [M] | 13.669, 13.091, 12.976 s | 13.386, 13.355 s; last cold fails |
| Native prove, same warm observations [M] | 4.728, 4.670, 4.773 s | 5.451, 5.709 s |
| Recursion, same warm observations [M] | 6.278, 5.823, 5.739 s | 5.540, 5.193 s |
| Largest affected role arena requested [M] | 11,240,738,728 bytes | 2,181,038,080 bytes |
| Whole-request kernel GPU-seconds / busy | unavailable | unavailable |
| Exact per-node peak | unmeasured | unmeasured |
| Root proof bytes, completed requests [M] | 749,688 | 749,688; byte-identical |
| Fresh CPU accepts, headline requests [M] | 6 | 4; failed request has no root |

These are individual observations from an incomplete interleaved run, not
final arm medians. The quiet protocol uses five stable idle intervals with
at most 0.5% cgroup PSI, zero throttling and exclusive GPU ownership. Historical
12.9 s is not a matched baseline for this attempt. Requested role arenas do
not measure whole-node or whole-process peaks.

The final candidate service fails at node 14 witness with
`NativePostGlobalDrainUnavailable`, then poisons the peer node. Its admission
model requests 28,621,930,496 bytes against 23,085,449,216 capacity [D]. The
peer node 9 INTER trace commit subsequently completes. The smaller composition
arena therefore does not robustly close the remaining future-footprint
constraint. All ten completed headline payload sets are identical and all ten
fresh CPU receivers accept [M]. The failed request has 34 matching partial
payload files and no root [M]; this is not an accepted proof.

The original post-abort script compared flat partial paths with grouped
canonical fingerprint categories. Its partial-match boolean and missing list
are invalid. `p1-outer-chunks-partial-audit-20261106-01/audit.json` corrects
those fields by hashing each file against the retained accepted reference;
all 34 present files match, five payloads are missing [M]. Completed-proof
byte comparisons and fresh receiver verdicts are unaffected.

The independent preservation gate **PASSES**: build, five Zig targets,
Python tests, both small-block proofs matching all 32 frozen payloads,
two fresh CPU accepts and all 19 corpus cases [M]. V04 cross-block-root
rejects by size cap, not semantic verification. The 81-file gate archive
was hash-verified locally and its source map matches the current source.
Receipt: `p1-outer-chunks-gate-evidence-20261106-02/p1-outer-chunks-gate-20261106-02/gate.json`.
The original gate/profile controllers aborted before doing work because the
primary experiment failed. No profile retry on this source is justified.
This correctness pass does not qualify the incomplete headline experiment.

Default: D2 + truth coalescing, automatic arena, one lane. All three P1 flags
remain off. Conjectured-128 security and proof format are unchanged.

Next: remove actual INTER numerator storage and reduce streaming state-bank
residency; audit the PCS phase lifetimes before replacing its deliberately
summed allocation envelope. The static screen in `remaining-memory-screen.json`
and hypothesis in `stream-compact-state-hypothesis.json` are not implementations or
peak-memory qualification. Do not add admission coordination or relax checks
to hide the failed footprint.

Evidence: `outer-chunks-hypothesis.json`,
`p1-outer-chunks-build-evidence-20261106-01/`,
`p1-outer-chunks-evidence-20261106-01/`, and the corrected partial audit.
The 618-file runtime evidence archive was hash-verified locally. Nine freshly
accepted duplicate proof sets were pruned after exact hash comparison;
756 MB freed [M], with the first accepted reference, failed request, all logs
and fingerprints retained. The M8 ledger validates; the global ledger checker
still has the historical missing commit in `device-fs.jsonl:1`.
