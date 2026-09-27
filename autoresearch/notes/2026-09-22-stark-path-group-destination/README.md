# Merkle groups emit into STARK path G/XOR storage

STARK path assembly reserves exact unused ranges in its live and fixed G/XOR
lists. Group builders borrow these ranges and frame builders write through into
the same storage. The group-to-path G/XOR append copies and group-owned hash
buffers are removed on this path. Smaller cohorts retain their existing append
logic. Publication follows live/fixed generation and root/payload-use checks;
query-read rollback and whole-preparation failure cleanup remain intact.

The owning group API and destination API share one builder. Required row sizing
uses canonical hash plans; the builder independently validates statements and
exact destination sizes. Sizing is not an admission token. Pointers are used only
during an opening; no borrowed group pointers survive later path-list growth.

## Qualification

Focused ReleaseSafe frame/native gates pass 8/8 steps, 4/4 tests. Frame gate (7 s,
3 MiB reported MaxRSS) includes owned/borrowed group live/fixed parity, receipts
not freeing caller rows, invalid destination geometry before writes, and exhaustive
allocation failures through group/frame ownership. Native gate (45 s, 2 GiB
reported MaxRSS) independently verifies both parent proofs, codec, handoff parity,
budget checks and ownership after worker destruction.

Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`;
codec remains 116,382 bytes. Handoff retention 130,557,704; worker peak 982,008,191;
preparation peak 622,506,697 bytes, all unchanged from the immediately prior stage.
No peak-memory or timing improvement is claimed from this copy removal. Planning
counts adds work; a dedicated timing comparison is still needed.

An earlier experiment restored frame encoding allocation order. Its tests passed,
but preparation peak rose to 623,859,426; it was rejected and reverted. That
hypothesis did not explain the outstanding regression from the older 600,657,997
baseline. Logs and experiment note are retained here.

Hash rows now bypass per-frame and per-group staging in STARK path assembly, but
path arrays are still logical rows and are projected later into native columns.
Transcript direct emission and the remaining row-to-column boundary are unfinished.
The preparation regression also remains open. Production security profiles,
reusable keys, distinct-child/parent-of-parent proofs, Metal and separately reviewed
parameter experiments are not qualified by these diagnostic tests.
