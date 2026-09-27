# Full BLAKE3 hash circuit — 2026-09-21

Previous turn: progress (complete compression STARK). This turn implements the
full unkeyed 32-byte hash construction over the same typed arithmetic and wire
relation, then produces real CPU hash proofs. Production migration and the
original four-part recursion performance goal remain incomplete and active.

## Implemented

`blake3_hash_plan.zig` derives a deterministic DAG from public input length:

- At least one block/chunk, including empty input; exact partial-word/block
  zero padding and byte lengths.
- Sequential compression within each 1024-byte chunk, original chunk-index
  counters, CHUNK_START/CHUNK_END flags.
- Left-complete binary tree: largest power-of-two left subtree strictly below
  total chunks, then remaining right subtree. Parent blocks concatenate child
  chaining values and use counter zero, length 64, and PARENT.
- ROOT only on the final compression of the root node; first eight output
  words serialized little-endian are the 32-byte hash. No unused root CV pass.
- Global wire IDs reuse predecessor outputs across compression calls. All
  multiplicities derive from actual consumers plus eight digest boundary words.
  Only constants/message words and final digest need boundary rows.
- Checked graph-size admission before allocation prevents M31 wire-ID aliasing.

Specification source:
https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex
(Tree Structure and Compression Function). Arithmetic implementation is our
existing shared G author, not copied upstream code. The Zig standard hash is an
independent output oracle.

`blake3_hash_witness.zig` writes the G, XOR and boundary rows from this graph.
Verifier projection reconstructs the graph and fixed rows from public statement
bytes and length, without evaluating private compression rounds. G/XOR fixed-row
writers now share schedule encoding with live-row writers and avoid redundant
arithmetic during preprocessing. The compression and full-hash proof gates share
one prover/verifier harness; no duplicate proof assembly implementation.

## Evidence

Five guarded tests across two targets:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-proof test-blake3-hash -Doptimize=ReleaseSafe --summary all
```

- Native witness digest matches std BLAKE3 for 18 lengths: 0, 1, 3, 4, 63, 64,
  65, 127, 128, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 8193.
- Fixed witness columns match independently reconstructed statement columns.
- Exact global wire multiset closes; altered cross-block CV byte, root flag
  source or digest byte breaks closure. Graph/witness allocation failures unwind.
- Actual compression proof plus full-hash STARKs for 0, 65 and 2049 bytes use
  BLAKE3 commitments, transcript, composition and FRI, with the real 2^18 bitwise
  and 2^16 byte-pair providers. Core verification accepts each. Changed public
  output and substituted preprocessing root fail trusted-root admission.

Initial passing run: proof tests 8 seconds total, maximum RSS 361 MiB; graph tests
561 ms. These are dev-loop diagnostics, not controlled prover benchmarks. The
proof tests use eight queries, blowup 1, last-layer log degree 0 and zero PoW.
They do not establish production security or a production recursion speedup.
The final passing command log and exact source snapshots are pinned here.

## Remaining boundary

These are fixed-length **public-message** hash proofs. Private child-proof values
must still be bound into message wires through authenticated caller components.
Remaining required work: exact scheduled transcript framing, rejection sampling
and PoW; recursive Merkle paths; trusted protocol/key/wire versions; Metal native
hash kernels and recursive composition qualification; complete same-security
parent-of-parent and performance measurements. Existing product defaults remain
unchanged. Keyed hashing and XOF are not used by the experimental prover suite.

The source-conformance baseline remains 103 pre-existing finding identities;
this work does not claim that broader baseline is green.
