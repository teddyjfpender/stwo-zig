# Memory-source authentication equations candidate v1

Status: source-only, unqualified. Eight new source files; no canonical/shared file changes. No compiler, tests, commitments, STARK/recursive proofs, guest/segment/device jobs or benchmarks were run by the author. The JSON pins the candidate and read-only dependencies. The root owns qualification.

The equation path authenticates actual SHA256 compression/padding and BLAKE3 tree frames, not host digest callbacks. Full u32 words and u64 clocks are bit-ranged; packed tuples retain every limb. Streamed SHA states, canonical file bytes, sparse nonzero input words, initial-image insertions, touched before/final values, strict address ordering, and tree routing/root states communicate through distinct typed buses. Public-input partial words are zero-padded and addresses are derived from the independently pinned input base. Program addresses and register records are rejected. RW classification preserves the legitimate data/stack/IO union.

Every initial nonzero leaf is inserted from the canonical empty tree. Every final update shares the same sibling variables and direction bits on both sides of the root edit. Outside the 28-bit memory word-index range, siblings are fixed to the canonical empty defaults. The initial checkpoint and independent final root are constrained. Thus a correctly proved/closed schedule preserves untouched words; no touched-only image can stand in for the initial root.

`Protocol.admit` binds independent initial/endpoint pins to the existing mode1 source seal. `Stream.kindAt` reconstructs exact chunk kinds/ordinals from those pins, without a proposer-selected schedule. `Cursor.next` emits only bounded candidate witnesses. `Circuit.prepare` constructs a graph from independent admission/kind/sealed draws; private witness contents do not select its topology. Its public inputs include the actual relation challenges, eleven computed sums and the exact chunk identity. `prepareClosureWithChallenges` records aggregate equations, including the original packed initial/final buses. None of these APIs returns a source proof receipt. The pure `make`, `propose`, `prepareWithChallenges` APIs are equation/testing constructors, not independent admission or acceptance paths.

The cursor owns a 64-byte raw block, one SHA chaining state and one 30-sibling edit envelope. Each equation graph has an independently configured hard heap budget (default128MiB), plus a separate accepted-node limit (default1M). No full file/image is allocated. The accepted-node cap is checked before publication; the heap cap governs construction and local evaluation scratch. Allocation failures propagate and clean up stable budget owners.

Honest work accounting: if I,J are initial input/RW nonzero leaves and U is unique RAM touches, E=I+J+U edits require32E tree chunks and122E BLAKE3 compressions. Canonical decoded records addI+J+2U chunks; five SHA streams addsum(floor(L/64)+1) chunks. The fixture has105 chunks and366 BLAKE3 compressions, including a full-width untouched word. This bounded memory prototype is not a claim of block-scale performance or a proposed canonical hash layout.

Required before source authority: commit all private source/routing/state witness cells before source challenges; prove chunks with a genuine arithmetic proof/recursive leaf; independently reconstruct each graph and public input binding; prove exact-once coverage; connect all public chunk sums to the aggregate closure; bind the external initial/final sums to fresh sorted RAM receipts; add a typed durable/sealed source family and activate it in CoveragePlan. Existing SHA file pins, host-computed sums, local equation evaluations and chunk descriptors remain proposals. No successful cryptographic closure is claimed.

Root-only nonproving command:

```sh
python3 scripts/zig_protocol_test.py src/frontends/riscv/block_v5_memory_source_auth_test_root.zig -OReleaseFast -mcpu=native --test-filter "source auth "
```

Named subfilters permit bounded diagnosis: `source auth crypto:`, `source auth stream:`, `source auth metadata:`, `source auth symbolic:`, `source auth symbolic SHA:`, `source auth fault:`, `source auth zero:`, `source auth mutations:`, `source auth bodies:`. The SHA symbolic fixture performs real graph construction/evaluation; the stream fixture evaluates the complete105-chunk arithmetic schedule. All remain nonproving.
