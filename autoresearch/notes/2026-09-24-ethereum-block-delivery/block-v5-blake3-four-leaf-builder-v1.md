# Four-leaf BLAKE3 commitment construction

The original shared lifted builder already supported four-leaf dispatch, but BLAKE3 supplied only node hooks. BLAKE3 now implements both packed and direct-M31 leaf hooks. The original and compact hashers select them through the same shared dispatch at every admitted nonconstant domain size; two-leaf domains retain scalar tails. Lazy secure-coordinate hashing also selects the direct hook. Constant-column and incremental streaming commitments retain their existing paths.

The implementation handles complete unkeyed BLAKE3 message trees, including empty messages, exact chunk multiples and unbalanced multi-chunk trees. It reads four equal-length messages one compression block at a time, with no whole-message staging or heap hasher state. Uniform M31 columns supply canonical words directly and allocate no leaf packing scratch. Mixed lifted columns use one bounded four-leaf scratch buffer per worker. The compact hasher retains its admitted capacity and original streaming state. Protocol framing, full digests, field byte order, leaf order and left/right node order are unchanged.

Nine focused checks passed: independent standard-library message-tree parity across prefix/block/chunk boundaries through131073 payload bytes; unequal-length rejection; direct/packed/compact/scalar framing and endian parity through8192 columns; actual mixed lifting and batch geometry; empty leaves; lazy coordinate offset and every scalar tail; every builder allocation failure; actual original/compact commitments matching every independently constructed layer; and the bounded diagnostic below. Eight existing node/compression/frame/PoW/compact regression checks also passed. No STARK, recursion, guest, driver, segment or device was executed.

## Equal-work leaf-builder measurement

Host: Apple M5 Max, CPU, Zig0.15.2 ReleaseFast with native CPU target. Each sample builds16384 leaves, using the same immutable source columns and original row mappings. One warm run per implementation precedes four ABBA-order samples. The baseline hides only the new leaf hooks and instantiates the existing bounded streaming builder with the original hasher. Timers include leaf output and scratch allocations, column reads, lifting/staging, full BLAKE3 hashing and digest writes. Every digest is compared with independently encoded/std-hashed input before measurements and after every timed run. Timers exclude column construction, digest checking, upper Merkle layers, deallocation, inverse tables and all other proving phases.

| Columns | Shape | Existing builder median | Four-leaf median | Speedup |
|---:|---|---:|---:|---:|
| 4 | Uniform | 1.833 ms | 0.789 ms | 2.325× |
| 24 | Uniform | 3.624 ms | 1.447 ms | 2.505× |
| 54 | Uniform | 6.332 ms | 2.600 ms | 2.436× |
| 92 | Uniform | 10.451 ms | 4.507 ms | 2.319× |
| 170 | Uniform | 18.453 ms | 7.891 ms | 2.338× |
| 257 | Uniform | 28.493 ms | 14.157 ms | 2.013× |
| 92 | Mixed lifting | 10.367 ms | 5.387 ms | 1.924× |

These are short leaf-builder measurements, not whole-proof or block speedups. RSS, thread stacks, device memory and GPU throughput were not measured. Four-lane compression uses a bounded stack of chaining values; removing retained heap hashers does not establish a process-memory reduction by itself. Same-source complete proving and RSS remain outstanding, with segment proving stopped.

Raw samples and exact source hashes: [leaf log](cpu-performance-gates-v1/blake3-four-leaf-builder-v1.log), [regression log](cpu-performance-gates-v1/blake3-four-leaf-node-pow-regression-v1.log), [receipt](cpu-performance-gates-v1/blake3-four-leaf-builder-qualified-source-v1.json).

Reproduce only these bounded checks:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/prover/blake3_leaf_batch_test_root.zig 'BLAKE3 leaf batch' 'BLAKE3 bounded leaf builder'
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/prover/blake3_frame_batch_test_root.zig 'BLAKE3'
```
