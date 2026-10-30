# One-layout block proving: integration status

This is an experimental CPU architecture on `codex/ethereum-block-fast-lab`.
It is not yet a soundness-qualified standalone Ethereum block root, and no
complete Ethereum block timing is available.

The complete 12-child, two-segment fixture now passes at diagnostic q8/PoW0:
all original proof families, independent fixed-key derivation, exact mixed
fixed-data parity, intermediate-file/witness destruction, fresh final-root
verification and hostile mutations. The final proof is 176,114 bytes, with
103,064 bytes of claim metadata. The diagnostic run took 394.286 seconds and
charged peak allocation was 21,418,687,324 bytes. It includes independent setup,
fixed-data comparisons and hostile checks on a shared host; it is not a ranked
performance benchmark. Canonical security and Ethereum execution remain
unqualified. Receipt: `complete-mixed-root-qualification-20261028.json`.

## Execution and retention

The explicit partitioned publisher shares the original admitted replay loop.
Its first-round callback proves B6JP-v3: native semantic constraints plus one
complete relation partition, ordinary-access integer constraints and byte
requests. It then skips the old native STARK. This is a distinct wire protocol;
old native/companion artifacts cannot serve as its proofs.

Collection can retain native, ordinary-access, ROM, lookup, RAM-lane and range
first rounds. These optional CPU checkpoints are untrusted proving material,
with independently admitted geometry, roots, scope and resource bounds. They
never replace fresh proof verification. Sorted RAM is consumed and checked in
collection; retained proving does not perform a second sorted replay. Lookup
fixed tables are retained once and leased across groups. Caller and external
access retention are connected and pass focused restoration tests; their final
assembled publication gate remains pending. External selected-column recovery
still performs inverse transforms, so retention does not remove every FFT.
Capacity and legacy word-memory routes do
not silently use these policies.

The genuine two-segment publication gate uses a mixed SHA/Keccak/arithmetic/
load/store guest, enables retention, and requires one joint artifact per
segment with no old native or companion artifacts. Semantic compilation has
passed; runtime qualification exposed a sealed-layout mismatch: collection
sealed the legacy projection while publication independently required the
complete partitioned projection. An explicit partitioned assembly path now
selects the complete layout before sealing and challenge derivation; its
runtime gate now passes all 12 tests. The actual 20,494-cycle mixed workload
publishes exactly two joint proofs, reuses native/access/caller/external
checkpoints, and freshly verifies without separate native/companion artifacts.
The existing complete-bundle gate
passed real one- and four-segment cases with all six listed retained families,
then removed checkpoint files before independent fresh verification. Its
development receipt is `block-v6-retention-integration-correctness-20261028.json`;
these concurrent-compile timings are unranked. Optional coefficient retention
and caller retention were not in that executable.

## One verifier proof and complete global closure

Direct provider batching has passed an actual original range16, RAM, ROM and
native-lookup proof test with one recursive parent. Missing-child, changed-claim
and wrong-key cases are rejected. The mixed preparation joins native, provider,
caller and PAGE verifier rows before proving; it does not prove intermediate
wrappers merely to combine them again. The strengthened four-provider test
also roundtrips bounded claim-only metadata through independent admissions
and destroys original proofs, captures and first-round owners before proving
the parent.

The genuine source test now proves, encodes, decodes and freshly verifies its
RAW PAGE. The FOLD failure was localized to its bitwise table at logical row 2:
the producer copied logical counter arrays directly into the committed main
tree, whereas fixed columns and interactions used committed circle order.
The producer now calls `Counter.committedColumn`, matching the RAW path.
Hash, arithmetic, canonical and input-supplier base rows already passed direct
equation evaluation; the correction changes witness layout, not any equation.
The corrected Debug and clean ReleaseSafe gates each pass all 6 tests: original RAW and FOLD publication,
canonical encoding/decoding and fresh verification; exact source closure;
both original verifier bodies joined before one parent proof; and fresh parent
verification after removing original proof files and captures. Missing-page and
changed-source-claim cases reject. This fixture is an empty source with genuine
padded hash requests and root-fold equations, not an Ethereum execution proof.
The separate actual first-round regression passes all 3 tests and additionally
covers changed/shared/default/branch recipes with real BLAKE compressions;
restoring the old logical-order table is rejected. The clean ReleaseSafe run
contains no temporary row scans or per-component polynomial instrumentation.
The unified PAGE shape, codec and allocation-failure suite also passes all 20
tests, including rejection of malformed composition-tree shapes. These are
diagnostic q8/PoW0 proof gates, not canonical-security whole-block qualification.
The source parent uses canonical cloned public values; complete detached PAGE
claim transport with independently reconstructed context remains part of the
assembled root gate. See `source-fold-qualification-20261028.json` for receipts.

The subsequent real 20,494-cycle, two-segment mixed guest now qualifies all four
nonempty source pages: two RAW and two FOLD original proofs publish and freshly
verify, and all four recursive preparations match independently compiled fixed
rows, wires, contexts and namespaces. A genuine FOLD-claim regression clamps
the admission allocator to its metadata-only peak while reconstructing wide
data through a separate live-work allocator. Capture/preparation/collection
limits remain 512 MiB / 4 GiB / 8 GiB. The source phase reached 3.480 GB charged
peak. Its diagnostic times include independent setup comparisons and the
allocation regression, and are not a production performance benchmark.
See `nonempty-source-qualification-20261028.json`. This run later stopped in
caller-fused recursive preparation with `SamplePointLayoutMismatch`; it does
not qualify the complete mixed root.

The subsequent caller-focused checks now pass: four original-mask/cold-shape
checks and three native quotient/recursive DEEP checks. The original fused
caller uses a composition-domain Keccak +27 opening, while another existing
layout uses the physical trace-domain step. They now have distinct constrained
layout tags; neither permits arbitrary captured points. A second correction
allows committed **unsampled** columns above the FRI lifting size, matching
original PCS semantics; sampled columns remain bounded. Hostile layout,
mask-step and unsampled-to-sampled substitutions reject. These focused results
unblock the next complete integration run but do not qualify its final root.

That integration run then reached `InvalidParentQueryLink`: original PCS
expands a query into a taller commitment tree while preserving its parity bit,
but recursive path/projection construction supported only shrinking domains.
The shared mapping now follows the exact original expansion in live directions,
projected-index packing and independent fixed ports. Inserted zero directions
are linked to an explicitly zero-constrained DEEP query bit for tall-tree
profiles; Booleanity alone is insufficient. Three focused mapping/port tests
pass, including exhaustive small-domain comparison to original PCS and live/cold
fixed metadata parity. Three DEEP tests also pass, including a malicious zero
anchor changed to one with all dependent arithmetic recomputed. Existing graph
identities without taller commitments remain unchanged. Actual caller preparation
then passed on the real fixture: two native originals, four global providers,
and both caller originals prepare successfully, including exact caller-fused
live/independent fixed parity. The separately named provider-preparation gate
passed all 12 imported tests. It deliberately does not publish PAGE proofs or
prove a root, and its success marker explicitly states `complete_root=false`.
Its 33.058-second diagnostic run includes independent fixed reconstruction;
charged peak was 2,662,493,417 bytes. See
`nonempty-provider-qualification-20261028.json`. The subsequent complete-root
run also passed, as recorded at the top of this document.

The SHA1/Keccak1 fixture census records 10,799 sampled columns (307,752 raw
cells) and 4,340 unsampled columns (103,062 raw cells), totaling 410,814 raw
cells. Unsampled columns therefore contribute 25.09% of raw cells in this
fixture. No columns were pruned, and this census is not evidence of a measured
speedup or of the same distribution in an Ethereum block.

The root must authenticate every original physical claim, then close the
original per-window state/register equations, each of six lookup kinds within
its independently planned group, ROM fetches including terminal boundaries,
RAM transitions/ranges and initial/final source equations. A single scalar
residual is insufficient. The new source-public closure reconstructs original
PAGE frames rather than trusting serialized routing offsets. It leaves native,
caller, program and lookup obligations explicitly open.

The assembled all-family integration gate is now implemented: two execution
segments, original provider and caller proofs, and real source RAW/FOLD pages;
bounded claim-only encoding/decoding; independent admission reconstruction;
complete global algebra; and one final parent. Its receiver checks the expected
public-input bytes against the pinned length and digest. Intermediate files,
captures and producer witnesses are destroyed before final verification.
An independent fixed factory compiles every original verifier family from
admissions and public proposals, including both namespace rebases and MAIN
identifiers. The key comes from that factory, not the live witness.

Runtime qualification now passes for this complete diagnostic assembly.
Independent mixed setup exactly matches the live rows, wires and contexts;
the final proof freshly verifies after destroying producer artifacts. Earlier
native live/fixed setup parity passed 10 tests; range and RAM parity passed in
the first mixed run. Integration exposed and corrected a transcript retry
capacity accidentally set to a row limit, empty-ROM fixed paths incorrectly
requesting zero-width openings, and caller capture comparing trace logs with
FRI-expanded logs. Focused regressions cover the latter two. These corrections
preserve the original constraints and strict verification.

Mixed witness assembly now joins the admitted roster directly into its final
columns instead of repeatedly copying a growing prefix. Exact comparison to
the former binary joins and allocation-failure cleanup pass two focused tests.
No end-to-end speedup is claimed from this change yet.

Completion still requires canonical-security multi-segment qualification and
measured block-scale reduction. The diagnostic all-family root does not
establish those results. The first capsule
contains one proof plus bounded O(roster) public metadata; it is not
constant-size metadata. Its current direct roster limit is 64 children.

## Native-only retention evidence

`block-v6-native-retention-development-m5-20261028.{csv,json}` records the
single idle-host A/B with the same executable, canonical q70/PoW26 and the same
1,310,734-cycle guest. It is explicitly a development-build receipt: the exact
source patch was not frozen, and it must not be promoted to a reproducible
release baseline.

| Segments | Recompute, seconds | Retain native only, seconds | Charged peak, recompute / retain |
|---|---:|---:|---:|
| 1 | 40.341 | 39.030 | 4.509 / 4.902 GB |
| 4 | 74.832 | 75.311 | 12.925 / 12.925 GB |

The native restore/recommit stage fell from approximately 0.561 to 0.23 seconds.
Full proof and bundle hashes were identical between modes. Total time is mixed
and the one-segment peak is higher; retention stays optional. This experiment
contains no access/global/caller retention, no new single-layout proving, and
no standalone root. Do not multiply this stage ratio by other isolated gains.

## Development measurements

Focused semantic checks (`-fno-emit-bin`) precede expensive code generation.
For expanded recursive-verifier correctness gates, `-O ReleaseSafe -fstrip`
retains safety checks while avoiding the observed LLVM debug-information
bottleneck. Correctness runs alongside compilation are unranked. Timing runs
require a quiet host, identical security/workload, proof verification and
complete stage/peak-memory accounting.
