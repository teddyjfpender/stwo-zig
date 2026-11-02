# ALU joint-prefix encoding v3

The existing concrete Word16 ALU keeps MAIN52, the same 53 local arithmetic
residuals, the same SUM-zero/signed-less staging, and twenty U16 queries per
physical row. Encoding v3 changes INTER52 to48 and total constraints69 to67.
No runtime policy enum or alternate integer interpreter is introduced.

## Exact ledger and degree

Twenty affine U16 denominators already use ten strict pair inverses: forty
M31 columns. The affine FUNCTION13 denominator uses four inverse columns.
Previously U16 and FUNCTION each had a four-column cyclic prefix. One shared
four-column prefix now authenticates their combined contribution:

`sum(1/range_denominator) - multiplicity/function_denominator`.

Each strict pair emits `dx*dy*inverse - 1` (degree3). A range pair contributes
`(dx+dy)*inverse` (degree2). The FUNCTION inverse is strict even at zero weight;
its weighted contribution has degree2. The joint cyclic prefix and last-row
zero anchor have degree at most2. The first53 arithmetic residuals remain in
exactly their old order. Dense arbitrary-Q tests check all67 residuals and
require a nonzero cubic term.

This architecture needs48 interaction columns, not24: twenty-one strict
fractions occupy eleven secure inverse groups (44M31) plus one secure prefix.
Native sources retain two claim summaries for dictionary validation and return
the existing `Claims{range16,function}` fields. Only their **sum** is certified
by the ALU polynomial. They are transcript-bound ledger fields, not separate
per-family certificates. Full-core closure already sums all physical debts;
the standalone diagnostic additionally closes against the separately proved
U16 table and independently expected FUNCTION consumer. A four-way balanced
claim mutation preserves both caller closure equations and the ALU total yet
fails actual verification because every claim enters Fiat–Shamir and the other
components bind their own claims.

## Source and arithmetic lanes

FN inverse columns are40..43; the joint prefix is44..47. Serial construction
and the existing two-wave parallel interaction constructor share the same
layout and retain exact claims. Native constructors, 70-byte row metadata,
multiplicity admission, inverse cache and MAIN ownership are unchanged. MAIN
may be released before interactions. Failed submissions/allocations preserve
unpublished output and permit retry after worker drain.

Native domain evaluation remains PackedM31 with PackedQM31 accumulation; OODS
uses QM31. The complete polynomial also accepts an external constant arithmetic
lane through `ChallengesFor`/`ClaimsFor`, preserving the exact native types.
The neutral scalar range helper now exposes `affineDenominatorFor`; the old
method delegates its unchanged expression to that authority. CircuitLane tests
wire all constants and compare all67 residuals, including changed range and
FUNCTION challenges and the total claim. A balanced split mutation deliberately
leaves the polynomial unchanged, documenting its actual certificate boundary.
This is arithmetic-lane parity, not a new recursive receiver claim.

## Encoding, callers and recovered roster guards

`alu_encoding.VERSION=3` and its identity bind the new prefix layout. Existing
standalone/raw/index callers bind that identity; the full Word16 core now also
mixes it explicitly before stage1 commitments/challenges. Payload13 operation
IDs0..9, public facts and all range masses are unchanged.

Broad requalification exposed two pre-existing stale BINARY widths: raw
`word16/cpu_materials.zig` and indexed `word16_index/materials.zig` hardcoded28
interaction columns although the current BINARY source has24. Both now derive
MAIN/INTER from canonical BINARY constants. The old mismatch caused
`InvalidThinCpuColumnShape` before proving. Fresh raw/index proofs qualify the
recovered integration; this is not a claim that an obsolete28-column artifact
has the new proof bytes. Historical receipts are retained unchanged.

## Costs and qualification

Per ALU row, current cells decrease106 to102; opened M31 values including
previous prefixes decrease114 to106. At actual ALU log20 this saves4,194,304
M31 source cells (16MiB). The 2n current evaluation matrix saves32MiB. Previous
openings are samples; they are not counted again as an invented full matrix.
No whole-job timing improvement is claimed from these counts.

The three-component log5 ALU/public-consumer/U16 diagnostic uses791,488 source
cells and182 opened M31 values. Its q70/P26 proof is261,248 bytes, SHA256
`5add6b786ded10b96dd59adcf3d0dde43336dc2ed0a43742872dfb31309d2265`.
Safe/Fast bytes match; separate fresh receivers accept. Invalid result, carry,
sign range and forged SUM-zero range witnesses fail actual proving. Source and
native kernel tests cover arbitrary secure/base lanes, released MAIN, weighted
facts, strict zero-weight poles, allocation failures, cancellation and exact
serial/parallel interaction equality with1/4/16workers. Closed raw/index/core
and shared-K integration gates are listed in the qualification receipt.

The unchanged BINARY diagnostic regenerated its retained q70 proof exactly:
SHA256 `9777c317201e1cdceb91f37f6a05d1a69ffb760040446aa502686202c1e3253f`,
and a fresh receiver accepts it. ALU representation changes intentionally use
new proof pins; semantic/fact and independent-authority checks are the contract.
