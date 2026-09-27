# BLAKE3 CPU frame batching

The source implementation uses four independent compression lanes for lifted
BLAKE3 Merkle nodes. `MerkleHasher.hashChildrenWithSeed4` uses `Frame.hash4`,
which writes each frame through the existing canonical `Frame.write` encoder.
The existing lifted layer builder already dispatches this four-node method;
the compact leaf hasher forwards the same method. Scalar upper layers and
worker-range tails retain the original node function.

`core/crypto/blake3_compression_batch.zig` shares the canonical seven-round G
schedule with scalar and recursive arithmetic authorship. Every lane retains
its own chaining value, 64-bit counter, block length and flags. Node frames
remain protocol prefix + node tag + left digest + right digest, compressed as
64 bytes followed by 28 bytes with CHUNK_END and ROOT on the second block.
They do not use the raw BLAKE3 PARENT flag. Fixed frame batches need only bounded
stack buffers. Variable-size frames use the existing streaming implementation.

The PoW four-candidate helper now uses this shared compressor. Its existing
prefix chaining value and terminal eight-byte nonce block, candidate order,
nonce carry and difficulty predicate are unchanged. This removes a separate
copy of the vector G schedule; it does not introduce a new transcript protocol.

Source fixtures cover independent standard-library digest parity at mixed
message/block lengths, compression output words and 64-bit counters, exact
node framing, mixed variable-frame fallback, nonce boundaries, and every layer
of a 32-leaf tree including the compact alias and subtree traversal. The focused
root is `src/prover/blake3_frame_batch_test_root.zig`.

Compression, mixed chunk-boundary/cap and mixed-frame checks are declared
directly in that prover root. Importing core declarations alone does not run
the separate core module's tests. The root also checks that the optional CPU
diagnostic rejects its iteration bounds before doing any timed work.

`src/prover/blake3_frame_batch_benchmark.zig` exports opt-in
`run(iterations: u32) !Report`, capped at 65,536 iterations, using stack storage
and four ABBA-order samples. Each path processes four independent framed nodes
or four nonce final blocks per iteration; dynamic outputs must agree. Nonce
measurements share the same previously compressed prefix and do not search for
a successful nonce. No diagnostic runs on import. The bounded kernel test
processed16,384 operations per path for four ABBA-order samples; its raw
timings are retained in the performance evidence directory.

All seven focused root checks passed in ReleaseFast on the current CPU.
The separate bounded kernel diagnostic also passed dynamic-output equality.
The short samples favor batching but vary; no end-to-end speedup or
full-prover qualification is claimed. Streaming leaf hashing and
variable transcript frames still use the standard BLAKE3 implementation; scalar
short frames already used the local canonical compressor before this change.

Evidence: [digest parity log](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/blake3-frame-digest-parity.log) and [raw kernel measurements](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/blake3-node-pow-kernel-measurements.json).
