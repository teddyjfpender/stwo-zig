# Width-bounded staged BLAKE3 leaf state

2026-09-22. Implemented compact staged BLAKE3 absorption using the already
qualified canonical leaf framing and compression owner. Input consists of at
most 16 columns per dispatch, a sequential first-column cursor, source/destination
lifting logs and explicit persistent-state stride. Source state is lifted to
the destination domain before new columns are absorbed. Final stages emit the
canonical eight-word digest directly; no separate digest-packing pass is needed.

State contains CV[8], pending block[16] and live chunk CVs. Counters are derived
from first_column + seven framing words rather than stored per resident row.
`Runtime.blake3LeafStateWords(total_columns)` bounds capacity by the width:
24 + 8 * bit_width((total_columns+6)/256). The standalone runtime validates
live input/output stack capacity, column/buffer bounds, sequential count overflow,
state-stride limits and non-overlapping destinations. Unused stack slots are
not read or written. The host remains responsible for the correct sequential
cursor, as with the existing staged hashing interface.

Final ReleaseSafe gate: 18/18 tests, 6/6 steps (12 staged/imported tests plus six
shader-authority tests). The actual device test hashes widths 17,249,250,505,
762,2042 with batch pattern 1,8,16,7,15 and increasing column/lifting logs. It
independently finishes each prefix before retaining that stage for continuation.
All 3,164 prefix digests match CPU across 415 stages, spanning partial/full
blocks, delayed exact chunk endings and multiple chunk-tree merges. Arena
checks preserve input columns, destination guards and poisoned unused stack
slots. Invalid overlapping state, undersized stride and short output reject.

Tested state strides: 24,24,32,32,40,56 words (96 through 224 bytes per row).
The full u32 width bound is 224 words, but that capacity is not allocated in
every row. Device execution used source JIT. Source inventory now has 173 core
and 178 Ethereum exports; the pinned AOT source digest and declaration registry
match. This is inventory validation, not AOT execution qualification.

Commands:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-staged-leaves test-shader-authority -Doptimize=ReleaseSafe --summary all
```

Remaining integration: this is the compact stage primitive. The reusable
resident-tree plan must adopt width-dependent state allocation and a shared
command encoder so stages run in one command batch. The existing Poseidon
scheduler assumes 16 state words and in-place same-log chunk updates, whereas
this primitive currently requires disjoint source/destination and can alternate
two bounded buffers per chunk. Do not admit BLAKE3 globally until all selected
paths (including wide commitments, transcript/cascade and decommit) are ready.
Full Metal proofs, prover-owned Poseidon identities and production recursion
remain unqualified. No CSP, recursion or end-to-end speedup is claimed here.

Algorithm mapping and source: archived 20260922-metal-blake3-staged-state-match.md.
Logs, changed-source snapshots and relative SHA256SUMS accompany this result.
