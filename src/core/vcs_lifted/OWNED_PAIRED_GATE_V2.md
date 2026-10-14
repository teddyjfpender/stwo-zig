# Candidate owned paired Gate transcript

`owned_paired_gate_v2.zig` is a candidate custody boundary for the reserved
`S31NAT9F` protocol. It is not selected by a production verifier.

`OwnedPairedGateVerifierV2.init` validates and hashes the line manifest once,
checks its digest and key digest against the statement, copies the fold roster
and opening shapes, and allocates the event plan and admitted cache together.
The cache points at the channel inside that stable allocation. Its opaque API
returns no mutable plan, channel, root cache, or query position slice. It
destroys the cache and sampled queries before freeing the allocation.

The public methods follow the proposed four-source-root, two-FRI-track order.
The two line-root methods check the current track and fold height, absorb a
root at its named event, and retain that same root for Merkle opening checks.
The event plan advances only after successful capture. The terminal sampler
keeps raw query words and sampled positions inside the object, and exposes
individual positions by value. Opening checks use the captured root and
copied row width and tree height; the manifest is not rehashed per opening.

For this candidate, the first fold height `k` is the raw query-domain log
size. Fold heights must be `k, k-1, ...`, and each nonterminal original and
own-quotient line tree must have `tree_log_size = fold_height - 1`. A sampled
raw position is always less than `2^k`. At line tree `i`, the selected row is
`raw >> (i+1)` in bit-reversed FRI query order; equivalently it is
`raw >> (k - tree_log_size)`. The public opening API takes a sampled query
ordinal and derives this leaf index privately. It rejects an ordinal beyond
the stored query count and a mismatched fold/tree height. A valid opening
for the other leaf cannot be replayed at the selected ordinal. The adjacent
line row also needed by a full fold relation is not yet authenticated here.
The projection matches the selected row of the pair opened in the experimental
`paired_sparse_cascade_heights_experimental.zig` verifier, whose pair base is
`((raw >> (i+2)) << 1)` for line tree `i`.

`verifyAndReadLinePair` authenticates **both** rows at `pair_base` and
`pair_base+1` under one captured root. Each row has four canonical M31 words,
forming one QM31 line value. `verifyAndReadBothTrackPairs` does this for the
original and own-quotient tracks together and returns no values unless all
four paths verify. Neither method accepts a leaf index. A wrong neighbor or a
replayed path at the other position fails its Merkle check.

`initWithSourceRoster` additionally admits an H1 source profile. All source
columns must have log size `k`, and the composition tree must have eight
columns. The source descriptor encodes `S31SRC2V`, the fixed source hash
profile, its two eight-byte BLAKE2s contexts, the key digest, root ordinal,
named root event, query log, column count, and each column's little-endian
log plus full 32-byte identity in order. The four named root events are
`1, 4, 10, 12`. The descriptor is framed under `tree_context` event zero and
must match the corresponding statement digest before the object is created.
The source profile uses `S31S2LEF` for canonical M31 row leaves and
`S31S2PAR` for 64-byte `left || right` parents. It is distinct from the
production plain profile and the candidate line profile. The fixed profile
and complete column roster are checked once; the selected verifier still
must derive the key, identities, and statement from one sealed source.

At an H1 query ordinal, `verifyAndKeepSourcePair` derives the source pair
indices `raw & ~1` and `(raw & ~1)+1` from the privately stored raw query.
It checks both rows in all four personalized source trees against roots
absorbed in this same transcript. The caller supplies only row values and
Merkle witnesses. The verifier converts its own OOD seed to a point, retains
the canonical claims it mixed into the transcript, draws its own batch
challenge, and computes CAS09's `RowContext` formula over the authenticated
columns in roster order. It privately retains two original and two
own-quotient insertion values per query. A wrong root, row, or pair index
fails; malformed or noncanonical claims fail before transcript absorption.
An arbitrary canonical claim remains only a transcript-bound assertion at this
stage. Its correctness against the committed source polynomials requires the
quotient/fold and degree checks; the local source-path API cannot reject such
a wrong claim on its own.

The original `initWithSourceRoster` entry remains H1 only. Sparse,
lower-height columns use the distinct versioned admission below.

The separate `initWithSparseH3SourceRoster` candidate admits the accepted
sparse Gate **shape**: top query log 17; source logs 17, 11, and 5; and four
tree widths 12, 17, 24, and 8. The per-tree height buckets are
`(1,8,3)`, `(1,12,4)`, `(4,8,12)`, and `(8,0,0)` in descending log order.
The interaction tree has twelve two-sample columns (indices 4–7 and 16–23),
so 61 source columns carry 73 explicit OOD claims. Its `S31SRC3V` source
descriptor binds each ordered column's 32-byte identity, log, and one or two
signed mask offsets, as well as the key digest, source hash profile, named
root event, query log 17, and mask log 16. Integer fields use little-endian
widths: root event 8 bytes, logs/counts 4 bytes, and offsets 4 bytes. The
source descriptor is framed under `tree_context` event zero; the single-column
Python BLAKE2s byte vector is pinned in the native test. An admitted manifest
must contain consecutive fold heights from 17 through at least 4, so all
three populated source heights have a fold step.

**Blocking paired-ensemble mismatch.** The current H3 original accumulator
advances once per source column: 14, 28, and 19 terms at heights 17, 11, and
5, for **61** total. The native `friAnswers` quotient accumulator advances
once per explicit claim **plus** one extra periodicity term per two-sample
column: 22, 36, and 27 terms, for **85** total (73 explicit + 12 extra).
The admitted roster computes and exposes these counts via
`sparseH3TermCounts`; mutation of a two-sample column is rejected. At a
height-local call (`lifting_log_size == column_log_size == h`), the periodic
generator raised by `2^h` is the identity, so the extra periodic point is
sample 1 again, with a second random power. Production uses lifting log 17
and therefore a different periodic point and coefficient schedule. This H3
insertion is an authenticated **local diagnostic**, not the matching
per-claim original/quotient ensemble in S-two Protocol 4 Eq. (77), a proven
degree-corrected oracle, or an established paper batch width `M`.

The same authenticated opening also retains a separate **literal 73-claim
receipt**. For each explicit claim in root/column/claim order it copies the
same authenticated source value and computes that claim's own quotient at
its normalized source-height OOD point. The twelve double-claim columns each
appear twice with the same source identity and different point/value/divisor;
no periodicity term enters this receipt. The per-height `(original, quotient)`
word counts are 36, 64, and 46 at heights 17, 11, and 5. A single batch
inversion handles all 146 row/claim denominators at one query. The receipt
is available one claim at a time for audit, but it does **not** fill the
paired-ensemble slot in the fold kernel: the common-Q and two-instance
theorems, lambda schedule, and source identity refinement remain open.
`verifyAndKeepSparseH3LiteralClaimPairs` authenticates the same four source
paths and retains just this receipt, skipping legacy diagnostic `friAnswers`
work. A repeated opening or failed path cannot overwrite the retained row.

At one privately sampled raw query, `verifyAndKeepSparseH3SourcePair` opens
the adjacent top leaves `raw & ~1` and `(raw & ~1)+1` under all four captured
personalized source roots. The lifted leaf has every column in ascending log
order, with stable column order within one log. Each lower column value at
top leaf position `r` is the source row
`((r >> (17-h+1)) << 1) | (r&1)`. Thus the two top leaves map to one adjacent
circle pair at each of h=17,11,5. The implementation checks the corresponding
circle-point doubling identity before deriving any inserted value. The S31
Lean lemma `SparseCascadeQueries.lean` at merged commit `9feb12b9` proves the
general canonical-index identity at the model level; the native point and
Merkle checks are separate obligations.

For each populated height, the candidate derives OOD sample points from the
privately drawn OOD point and the bound signed mask offsets. It doubles those
points `17-h` times and evaluates the quotient at the projected height-h
circle row. This normalization matches native prover source evaluation:
`sampled_values.zig` computes `fold_count = 17-h`, and
`sampled_coefficient_plans.zig` doubles each sampled point before polynomial
evaluation. The accepted sparse Gate admission in S31 `native_verifier.zig`
rederives the top mask points from sealed AIR handles and checks all 73
captured point coordinates and values; its accepted H3 row fixture compares
projected row arithmetic for all 73. These are finite source-bound checks,
not a general interpolant theorem.

The two-sample columns receive the native periodic sample first, then their
two explicit claims. Powers of the privately drawn batch challenge follow
the source-column and sample order **within that height**. The original
track is one separately batched source value per column at that height. These
two track insertions are retained privately per sampled ordinal only after
every source path and every height computation succeeds. This per-height
batch choice is part of this candidate diagnostic; it does not implement
the accepted production quotient schedule or Protocol 4 Eq. (77). The implementation
currently calls the production quotient evaluator per height and query, which
rebuilds temporary sample batches and constants. A selected verifier needs a
one-time cached quotient context and a measured whole-verifier cost model.

The focused H3 tests pin the accepted 17→11 and 17→5 projections for both
sides of raw query 90528, which map to source pairs 1414/1415 and 22/23.
They check changed bucket counts, mask-offset descriptor mutation, a wrong
query ordinal, repeated raw queries, inconsistent repeated rows, wrong paths,
the exact 18/32/23 explicit-claim counts, repeated original values under
one double-claim column, and a nonzero two-sample quotient against an independently constructed
one-column row context. The tests use synthetic personalized source trees;
the local arithmetic test seeds the owner's private transcript state directly
to isolate the opening calculation, so it does not exercise full event replay;
the accepted production proof has plain source roots and cannot be replayed
under them. A selected S31 adapter still must derive every column identity,
log, and mask offset from the installed sealed key, then own the statement and
proof geometry. Degree testing, the multi-context BCS reduction, and
query-consistency theorem remain open. Native proven security bits stay unset.

### H3 committed and terminal fold kernels

`verifySparseH3CommittedStepAtQuery` checks each of the 13 committed steps
from height 17 down through the insertion at height 5. It authenticates both
adjacent rows of both line tracks under privately captured roots, derives the
selected row from the retained raw query, and uses the exact verifier-drawn
alpha for that height. At the first height it folds the source pair into the
line. At later heights its pointwise Eq. (68) recurrence is:

```text
next = fold(previous_line_pair, line_x, alpha)
     + alpha² * fold(source_circle_pair, circle_y, alpha)   # at h=11 or h=5
next = fold(previous_line_pair, line_x, alpha)              # other heights
fold(a,b,c,alpha) = a + b + alpha * (a-b)/c
```

The line and circle domains are checked to share the expected doubled coset.
The source pair comes from a **separate private paired-ensemble slot**. No
public operation currently admits that slot: `verifyAndKeepSparseH3SourcePair`
fills only its diagnostic 61/85 row slot, and a normal call to the fold
kernel returns `SourceEnsembleNotAdmitted`. This prevents the diagnostic
quotient from silently becoming an Eq. (77) source. A test-only private
fixture populates the paired slot, replays all 13 drawn challenges against
authenticated zero line trees, and rejects changed alphas, source words,
both line paths, missing slots, and wrong ordinals.

`verifySparseH3TerminalAtQuery` then checks the last height-4 fold into the
terminal log-3 line domain. For each sampled query it first requires a
successful check of **all 13 committed steps**. It authenticates both
adjacent height-4 line rows under the captured original and own-quotient
roots, folds each pair using retained `alpha[13]`, and compares the result
at the privately projected terminal row to the corresponding polynomial.
The proposed B=2 terminal profile absorbs exactly two canonical QM31
coefficients per track before the final PoW and query draw. Wrong coefficient
length fails before transcript absorption. The terminal polynomial has
degree below 2; its evaluation domain has eight points. A local differential
checks all eight pair-to-terminal positions against native
`foldLineSingleStep` with a nonconstant terminal and changed-alpha control.

The public method still fails `SourceEnsembleNotAdmitted` because no public
operation fills the separate paired source slot. The literal 73-claim
opening path provides authenticated per-claim words but does not yet establish
the common-Q/two-instance source ensemble or admit its aggregate to the
fold cascade. The degree profile, sealed-key/roster ownership, full per-query
coverage, BCS reduction, and global FRI theorem remain open. Neither this
kernel nor the literal path is selected by a production verifier; neither
assigns paper M or security bits.

The literal path now also retains a **non-admitting candidate weighted row**
per height. It traverses the 73 explicit claims in captured root/column/claim
order, with 18, 32, and 23 claims at heights 17, 11, and 5. For each height
the list is `f₀,q₀,f₁,q₁,...`; its powers restart at one and advance once per
function, so claim `j` contributes `λ^(2j) fⱼ` to the original track and
`λ^(2j+1) qⱼ` to the own-quotient track. The 12 double-claim columns repeat
the identical authenticated original under two distinct exponents and use
their two distinct OOD quotient values. No legacy periodicity term enters.
`sparseH3CandidateWeightedAt` returns a copy for inspection; this cache is
separate from the paired source slot read by the fold checker.

This schedule implements the literal Protocol 3 Eq. (66) power order for a
*proposed* joint 73-pair list. It is not a theorem that a one-challenge
multi-Q batch extracts two point-specific quotients with the same original.
The current two-Q theorem instead assumes individually extracted instances
that agree with one authenticated source oracle on sufficiently large sets;
it does not derive those sets, a joint adaptive BCS bound, or this lambda
schedule from accepted native proofs. Thus weighted-row arithmetic is local
evidence only, and public fold admission remains closed.

The candidate `verifyH1OneStepAtQuery` checks the exact CAS09 two-step H1
relation for a restricted degree-zero terminal profile. It requires two fold
heights, initial query log `k >= 3`, one authenticated original and one
authenticated own-quotient line tree at log `k-1`, and exactly one canonical
QM31 terminal coefficient per track. The event plan draws `alpha[0]` before
the line roots and `alpha[1]` after them; the opaque owner retains both exact
draws. It checks, separately for each track:

```text
source_base  = raw & ~1
line_base    = (raw >> 1) & ~1
first       = fold(source_inserted[source_base..source_base+1], source_y, alpha[0])
first       = authenticated_line_pair[(raw >> 1) & 1]
second      = fold(authenticated_line_pair, line_x, alpha[1])
second      = terminal_poly(line_domain[raw >> 2])
fold(a,b,c,alpha) = a + b + alpha * (a - b) / c
```

The source insertion at the second height is zero for this H1 profile. The verifier
derives `source_y`, `line_x`, and the terminal position from checked circle
and line domains; it checks the circle point's first doubling against the
next-height projection. A differential test matches both butterfly stages
against production single-step FRI folding, including coset orientation.
The terminal polynomial is constant here. A general terminal degree needs a
sealed log-blowup/degree parameter and a later profile revision.

This local method takes only line row/path wire. It reads the sampled raw
position, source insertion, line roots, two alphas, and terminal coefficients
from private state. It returns a mismatch for a wrong equation; it does not
record a global proof-acceptance result. A selected verifier must call it for
every configured query and check the remaining AIR, commitment, degree, and
transcript conditions. At lower inserted source heights, the circle source
projection must preserve the original low bit:
`2 * (raw / 2^(i+1)) + raw % 2`; the folded line row uses
`raw / 2^(i+1)`. The H1 profile has no lower inserted source height and does
not establish that more general projection theorem.

Query draws reject a zero count without moving the transcript. Once the
terminal query event begins, any sampler failure leaves the plan complete and
cannot be retried on the same object. The query count and block cap still
come from the caller; a selected verifier must derive and freeze them from its
sealed configuration.

This boundary does not derive the statement or manifest from a sealed key.
The caller must supply both from trusted, checked verification data, including
four source-tree descriptors, the circuit digest, FRI parameters, and the
line-tree roster. The full PCS/FRI verifier, non-squaring FRI query
correspondence, and the BCS/ROM reduction across framed transcript hashes,
personalized source hashes, and personalized line hashes remain open. In
particular, the local tests do not establish a 96-bit collision bound for
any of those profiles. The published three-term collision bound cannot be
applied to this five-context hash family without a role-aware reduction and
query-count accounting. Native proven security bits remain unset. A `true`
Merkle opening result is only a local path check, never proof acceptance.

The focused tests check event order, named root absorption, descriptor byte
vectors against independent Python, copied metadata, source and line Merkle
paths, private query projection, claim shape, and rejection of wrong rows,
roots, and source pair indices. The fold controls include 232 raw query
ordinals over an eight-point domain (with repeats), a nonzero quotient
witness, wrong source rows/insertions, wrong adjacent line paths, both wrong
alphas, and terminal mismatches on both tracks. The number 232 exercises
custody and does not certify the selected `T = 2^64` work-factor target.
These are candidate API tests, not a PCS/FRI soundness proof.
