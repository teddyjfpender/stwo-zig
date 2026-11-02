# Receiver-derived candidate source bounds

This is an engineering preflight for the explicit beta2 OM31 candidate, not a whole-protocol security certificate. The benchmark control remains unchanged. Both the Ethereum producer and the independent candidate receiver run it before constructing immutable keys; library `Inventory` repeats it for candidate callers. Declarations select a validated shape, never a producer security certificate. Image, endpoints, physical roots, manifest coverage and global closure still require the accepting receiver.

`services/gkr_local/source_bounds.zig` derives role widths, masks, arithmetic degrees, constraint counts, local instance dimensions and physical query counts from the same metadata and fraction emitters as production. It counts the whole physical FIXED key, including legacy fixed columns unused by the new arithmetic. It refuses checked-overflow, unsupported shape and characteristic bounds before expensive setup. CPU/bridge local queries, including inactive padding, are counted. Keccak chi/xor consumers likewise use every physical row, not an honest active census. For example, a log-21 Keccak declaration with one claimed call fails the characteristic guard.

The JSON report is diagnostic. `security_qualified`, `transcript_round_bound_qualified` and `secp_polynomial_error_budget_qualified` remain false. Changing parameters or producer JSON cannot set them.

## Two different counting authorities

REG and OWNER have unit consistency on both sides. RAM, KIO and Wire remain separately closed global arguments with ordinary positive and negative integer bounds. `mass_authority.zig` derives these from admitted spans, before/after words and the immutable secp program's input, output and wire-use counts. It never interprets a field-valued claim as an integer count. Real CPU and truth fixtures independently enumerate the original raw emitters and check both signs against this authority.

ROM, FUNCTION, range, AND, SHIFT and selection use **unit consumer mass and valid provider support**. Provider multiplicities can be arbitrary field elements. Their support count is deliberately a different field from negative integer mass. It must not be passed to the older `Candidate.Facts` interface as an integer negative mass.

Conditionally on semantic support validity and absence of tuple-compression collisions, an invalid consumer tuple has residue of magnitude between one and the unit consumer count. A count strictly below the M31 characteristic cannot vanish. A provider supported only on valid tuples cannot cancel that invalid pole, even when valid provider weights split, duplicate or cancel. Clearing denominators gives a nonzero rational numerator of degree bounded by the number of physical denominator slots. This is a lookup-membership argument, not arbitrary weighted integer multiset equality.

All padded unit queries count toward the characteristic bound. Zero-weight denominators also count toward pole and collision bounds: their inverse obligations are still physical. Independent namespaces are counted independently; global RAM/KIO/Wire counts span the entire admitted execution. The report's conditional degrees conservatively use all slots, rather than claiming a measured distinct-support reduction.

## Canonicality premises and dependency order

The crucial auxiliary checks are unweighted. `fractions.zig:53-67` emits ALU range, BINARY AND, and SHIFT table/range requests with `F.one()` on every physical row. Only each negative FUNCTION yield uses the row's multiplicity. This prevents arbitrary FUNCTION weights from cancelling invalid auxiliary range facts. Regression tests inspect all these raw weights at zero, one and minus-one multiplicity. They test a polynomial identity, without pretending those arbitrary rows are valid witnesses.

The fixed range/AND/SHIFT/selection/ROM providers have immutable valid support regardless of their count columns. Main-only arithmetic retains activity, carry/borrow and inactive-multiplicity constraints. MUL byte queries and DIV range/sub-operation queries remain independent constraints; JALR delegates to ADD/AND and DIV delegates to MUL/MULHU. The semantic induction also needs canonical operands: the existing register/RAM induction and complete register-writer inventory apply, including LUI and AUIPC. See `rv64-ls32-qualification.md`, `rv64-ls-canonical-range-induction.md` and `rv64-ls32-recovered-review-20261101.md`. The preflight does not replace that induction with a lookup-count assertion.

Global active masses additionally rely on original physical span constraints, not merely a request's call census. Keccak activity is Boolean, ordered by fixed slot index and call id, with inactive suffix and final-id binding; bridge activity/call spans and secp's fixed program similarly bind their admitted counts. Wire's readonly use multiplicities are ordinary small integers from the immutable program. These remain part of the soundness review; the metadata checker alone is not a proof of the span lemma.

## Conditional error accounting and remaining gates

`requireLookupOnlyBits` accounts only for tuple collisions, rational identities and pole events under the raw-modulo sampler's existing maximum-point-mass bound. It deliberately omits GKR, polynomial compression, PCS, circle OODS, DEEP/FRI, adaptive Fiat-Shamir and recursion. The preflight requires this lookup-only inequality at the configured target. It is a necessary partial budget, never an overall security number.

Before a whole-128 claim, review the composed valid-support/canonicality induction, the actual adaptive transcript reduction and round bounds, the secp modular-polynomial compression term, authenticated GKR terminal/Eq-prefix binding, mixed-height circle/DEEP/FRI constants, and recursive outer error. The existing whole-protocol promotion gate stays closed. No new GPU kernel or GPU throughput claim is included.

## Qualification

The local-GKR suite passes ReleaseSafe and ReleaseFast, including source-shape refusal, full padded characteristic refusal, exact source sign counts, metadata consistency, raw unit-query invariance, split valid-provider algebra, bounded allocation failure and existing physical proof/fresh-receiver tests. The complete CPU/truth fixture passes ReleaseFast with the candidate library guard enabled. These are correctness/resource gates, not controlled performance measurements or a formal theorem review.
