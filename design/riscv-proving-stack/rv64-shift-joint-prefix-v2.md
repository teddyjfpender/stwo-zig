# Word16 SHIFT: strict cross-family pairs and one prefix

This concrete encoding keeps the qualified six-mode Word16 SHIFT arithmetic,
MAIN53, thirty-byte payload/multiplicity metadata and native constructors. It
changes INTER48 to36 and total constraints43 to38. The first27 arithmetic
residuals are unchanged. The BYTE SHIFT control and both Word16 truth tables
retain their arithmetic and table geometry.

The five SHIFT-table queries and nine U16 queries have affine denominators.
Flattening those fourteen unit-weight queries gives seven strict pairs:

`SHIFT0/1, SHIFT2/3, SHIFT4/U16_0, U16_1/2, U16_3/4, U16_5/6, U16_7/8`.

Each pair emits `d0*d1*inverse-1` and contributes
`(d0+d1)*inverse`. These equations are degree3 and degree2 respectively. The
FUNCTION13 query remains a separate strict inverse, contributing `-mu*inverse`.
Only FUNCTION is weighted. Physical table/range masses remain exactly5N/9N,
including padding and zero-weight facts. Even zero-weight FUNCTION poles fail.

Seven secure pair inverses occupy columns0..27, the FUNCTION inverse28..31,
and one cyclic prefix32..35. Its first correction binds the sum of the three
transcript-bound claim fields; its terminal anchor is zero. The three fields
remain useful native ledgers, but the SHIFT component certifies only their
sum. Callers must close every participating physical debt and must not treat
these fields as three independently authenticated certificates. The diagnostic
caller closes against separate SHIFT/U16 providers and an independently expected
FUNCTION consumer. A four-way balanced table/range claim attack keeps both
caller closures and the SHIFT total unchanged yet fails actual verification.

`shift_word_encoding` binds concrete version2, the algorithm identity and all
width/query constants before stage1 roots and relation draws. The full core and
both Word16 diagnostics mix it. This adds no runtime representation enum.
Native and OODS use one `emitFor`; the native domain remains PackedM31 with
PackedQM31 accumulation. The complete polynomial also has explicit external
constant arithmetic lanes, including claims/challenges as circuit wires.

Serial interaction construction keeps each native claim summary independently,
validates the same dictionaries/count ledgers, and writes one joint prefix.
The existing constructor's native parallel fill, ownership, multiplicity
admission and MAIN retirement are unchanged. Interaction generation itself is
serial; worker-count tests also qualify native construction and packed domain
code and are not an interaction-parallel speed claim.

Current cells decrease103 to91 per SHIFT row; sampled M31 values including
previous openings decrease115 to95. At log20 this removes48MiB of source and
96MiB from the current2n evaluation matrix. Previous openings are samples, not
a claimed additional full matrix allocation. Whole-job speed is unmeasured.

The packed-table log5 diagnostic has5,378,656 source cells and245 sampled M31
values. Its q70/P26 proof is276,832 bytes, SHA256
`c09d15cc92211060f377d8dfc2cf1aa682e6a42d65d70332d5b46a0719034b63`.
Native-owned, borrowed and independent scalar-oracle paths produce the same
proof. Separate fresh receivers verify; Safe/Fast byte parity and all focused
and joined fixture gates are recorded in the qualification receipt.

Qualification includes arbitrary-Q fourth differences with a genuine cubic
term, exact old arithmetic order, scalar/PackedM31/PackedQM31 residual parity,
complete CircuitLane parity and challenge/claim mutations, strict inactive
poles, high70001 multiplicities, retry/OOM/borrowed-input cleanup and constructor
worker drain. Real closed proofs reject bad result, table output, quotient and
sign aliases, changed prior openings, noncanonical claims and balanced debt
mutations. Full-core and shared-K fixture proofs exercise the new role; this
slice does not claim a new full-block or recursive acceptance protocol.
