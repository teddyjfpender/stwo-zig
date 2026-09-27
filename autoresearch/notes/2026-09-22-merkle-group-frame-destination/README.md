# Merkle frames write directly into group G/XOR storage

Merkle groups allocate their final G/XOR logical-row slices once. Exact counts
come from canonical leaf/node hash plans and checked leaf/merge counts. Each frame
borrows its final nonoverlapping range; digest output multiplicities update that
range directly. The former per-frame G/XOR buffers and group concatenation lists
are removed. Frame APIs support both live and independently built fixed rows;
the fixed path reuses the original canonical fixed-row equations.

Frame receipts allocate separately from the enclosing group arena. The group
explicitly destroys every appended receipt; not-yet-appended frames and failed
merge results have error cleanup. Receipts borrow G/XOR storage and cannot free
it. Smaller routing/boundary rows are copied before receipt destruction. Group
namespace, root, selector, payload-use and boundary filtering logic is preserved.

## Qualification

- FRI group gate: 1/1 passes (3 s /370 MiB reported MaxRSS), covering fold widths
  1, 2 and 4, complete subtree fixed/live parity and typed proof mutation rejection.
- Native parent gate: 3/3 passes (45 s /2 GiB reported MaxRSS), both independently
  verified parent proofs, codec, handoff parity and ownership checks.
- Frame gate: 1/1 passes (2 s /3 MiB reported MaxRSS), owned/borrowed live/fixed
  parity, invalid destination before writes, borrowed storage surviving receipt
  destruction, allocation failures including leaf/subtree/selected-path ownership.

The first combined run had a test-only failure: a malformed-destination assertion
inside the allocation-failure sweep received expected allocation exhaustion before
geometry validation. Negative geometry checks now run outside that sweep; the
positive ownership path remains fully failure-injected. Initial logs are retained.

Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.
Codec remains 116,382 bytes. Handoff retention remains 130,557,704 bytes and worker
peak remains 982,008,191 bytes. **Preparation peak increases from 600,657,997 to
622,506,697 bytes (+21,848,700)**. Separating frame receipt allocations did not
change this overall peak. Allocation order/arena capacity elsewhere is a hypothesis,
not an established cause. No peak-memory or timing win is claimed. This final-layout
change is retained as implementation progress with the regression explicitly open.

These are group-level logical destinations, not final native committed columns.
STARK path aggregation and transcript adapters still retain logical row staging.
Next resolve preparation allocation overlap and carry direct destinations through
those boundaries. Production security profiles, reusable keys, distinct-child and
parent-of-parent qualification, Metal and reviewed parameter experiments remain
unfinished.
