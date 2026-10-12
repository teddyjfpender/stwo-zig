# Canonical word-memory protocol v4

The sorted RAM path commits12 fixed,27 main and68 interaction base columns.
It uses46 direct and17 logup constraints, degree4 and expansion2.
No address, value, clock or ordinal is truncated: addresses/values remainu32
and clocks/ordinals remainu64. Non-Boolean main limbs use the independently
verified range16 provider.

Nine duplicated predecessor main columns and their copy/range equations were
removed in v3. Interior predecessors now come from authenticated shifted
current-key/current-clock/after openings; first-row predecessors come from the
independently pinned public preceding transition. Only those nine shifted main
columns are opened or gathered. Range-provider main columns need no shifted
opening. The ABI explicitly binds the mask grammar.

V4 additionally represents trusted current/previous ordinals as four16-bit
fixed limbs each. Active, first, last and domain-last selectors remain four
committed fixed columns. Global-first is first when the pinned first_row is
zero; global-last is last when the pinned instance ends at total_rows. Those
two selectors are no longer committed duplicate columns. The receiver builds
the exact same12 fixed columns from its independently supplied claim and checks
the fixed root. The transformations are linear in the original fixed selector
and byte-ordinal polynomials; the constraint degree stays four.

The explicit protocol version, ABI, memory instance and range plan domains
changed. Historical byte-fixed layouts are used only as independent parity
references and older noncanonical components; they are not selectable v4
production alternatives.

Five focused checks passed: fresh sorted/range/source/register/RW endpoint
verification, native byte projection/range rejection, exact OODS mask grammar,
packed/scalar previous-gather parity, and all fixed selectors/ordinal limbs at
16-bit,32-bit and maximumu64 boundaries including padding and nonterminal
instances. The fresh proof used diagnostic8-query/zero-PoW security; this is
not canonical-security complete-block qualification.

[Qualification log](../../../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/word-v4-fixed12-fresh-proof.log).
