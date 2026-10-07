# Production memory source staging

`block_v5_memory_source_writer_v1.write` consumes the production reopenable `SortedSource` and a complete borrowed initial image (`block_memory_replay.InitialWord`). It has no fixture imports and no 256-event ceiling. The driver supplies the independently admitted memory layout, public input, initial/final registers, exact event census and mandatory initial/final full-image RW roots. These roots include input and untouched nonzero words; a filtered per-segment `includeFinal()` image is not equivalent.

The writer creates four files exclusively: nonzero public-input words, nonzero initial RW words, exact ordered first touches, and last RW tuples. Their canonical records are the existing LE8, LE8, LE9 and LE16 source formats. Program words are separately classified and excluded from RW custody. Program first touches fail closed until the authenticated raw-ROM initial-value bridge exists. Public input comes from the independently supplied bytes, including a zero-padded final partial word; any supplied initial input word must match those bytes.

Each first touch must match the complete initial image or initial register array. Successive transitions for a key must have strictly increasing exact u64 clocks and matching before/after values. Last register tuples must match the independently supplied final array. Untouched registers remain unchanged with clock zero. The writer emits the exact global first-touch mask and final clocks used by the existing register endpoint policy.

Initial and final sparse roots reuse `TreeHasher` and the existing `byte_tree_topology` traversal through a fallible streaming adapter. The final image merges every last RW tuple with the complete initial image: touched zero values remove leaves, untouched leaves remain, and touched input words follow the same full-image semantics. No transition or endpoint array is retained. Errors and malformed sparse order propagate before a root can escape.

Four 8 KiB output buffers, the bounded production sorted reader, an 8 KiB endpoint-read buffer and depth30 root traversal fit a fixed 128 KiB logical workspace allowance. The writer checks this allowance, the borrowed-image census, event/touch caps and aggregate file length explicitly. This is a writer-workspace bound, not a whole-driver allocation or measured process-stack peak; the replay sorter and caller-owned initial image have their own lifetimes and budgets. Record counts also retain the protocol input/RW/touch maxima. Failed writes delete all files created by that call, and exclusive creation preserves an existing output.

The owned result contains open file handles, immutable SHA256/count pins, register endpoint pins, observed roots and exact counts. `endpointPins(actual_memory_plan_digest)` binds the later roots-only sorted-memory plan. Results are candidate source metadata. The driver must independently admit them into B5SS; fresh memory/range proofs and source/global relations still determine proof authority. Closing the result closes its handles and leaves the staged files for the owning driver.

The focused production writer and sparse-root gates passed 3/3 in ReleaseFast with `-lc -mcpu=native` and clean testing-allocator teardown. The test uses the real external sorter and production `Transition.Reader`, with 604 events, 603 distinct first touches and 602 RW endpoints. It preserves an untouched RW word, an untouched stack word, a partial public-input word and an unchanged register, removes a touched zero-valued leaf, and retains exact canonical access clocks with bit 48 set. The four files total 15,099 bytes. Existing production initial, endpoint and register checkers accepted all SHA/count pins and reconstructed the expected full final root.

Wrong independent initial/final roots, wrong first-before values, changed untouched registers, wrong event census, output/workspace cap failures and a modified endpoint file all rejected. Failed calls removed their partial outputs. The streaming-root test compared against the canonical sparse tree and rejected duplicate order, census overflow and an injected read failure. The first test attempt used noncanonical synthetic access slots and correctly failed at the sorter; the test clocks were corrected to the real stride4 convention without changing production clock validation. These gates qualify source staging and public custody metadata only; they generate no STARK or recursive proof and establish no complete block or whole-driver memory/timing measurement.

The focused command is:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py \
  --root src/frontends/riscv/block_v5_memory_source_writer_test_root.zig \
  'block-v5 production source writer' 'block-v5 streaming sparse roots'
```
