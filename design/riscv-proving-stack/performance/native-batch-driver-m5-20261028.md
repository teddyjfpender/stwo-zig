# Direct native aggregation in the actual complete-bundle driver

The replacement driver measures **87.195 → 32.992 seconds (2.64×)** at
70 queries / 26 PoW bits on the same two-segment, 307,214-cycle workload.
This is an actual driver comparison, not a subtraction of separately timed
stages. It is not an Ethereum-block measurement or a self-contained recursive
root: the receiver still needs the original global base proofs.

Implementation: `eb289f24a1ae90f1bd244b9c4743ab26b2aa439b` on
`codex/ethereum-block-fast-lab`. The new
`block_v6_cpu_native_batch_driver_v1.zig` removes individual native recursive
wrappers and the V5 forest. It retains collection, the original base proofs,
one bounded direct-native batch, publication, and fresh complete verification.
It currently accepts one to eight executions; larger jobs fail before collection.

## Matched measurements

Apple M5 CPU, eight workers, ReleaseFast, **one sample per profile**. Both
arms use register-local custody, the same ELF/input/endpoints, and the same
security configuration. The workload includes load/store and SHA/Keccak work.

| Measurement | Diagnostic q8/PoW0 | Canonical q70/PoW26 |
|---|---:|---:|
| Original driver | 23.454 s | 87.195 s |
| Replacement driver | 13.132 s | 32.992 s |
| Speedup | 1.79× | 2.64× |
| Collection | 1.479 s | 1.547 s |
| Base publication | 6.354 s | 8.882 s |
| Direct recursive batch | 3.470 s | 20.491 s |
| Fresh complete verification | 1.829 s | 2.072 s |
| Original charged allocation peak | 2.179 GB | 7.568 GB |
| Replacement charged allocation peak | 1.497 GB | 6.591 GB |

Within canonical recursion: preparation **9.521 s**, setup **2.152 s**, proving
**8.758 s**, encoding **0.031 s**. The remaining recursive stage time includes
publication and owner teardown. Preparation includes witness construction; it
must not be described as entirely cacheable setup.

The primary timer surrounds the driver invocation, including publication,
verification and teardown. Shared preflight and initial runner-source creation
are outside it. Additional detached verification after producer destruction
(1.859 s canonical) and hostile tests are also outside it. Family timers overlap
and cannot be added to the wall time. Memory is the shared driver's charged
allocator peak, not process RSS, and excludes the outer test's retained baseline
metadata. GB above is decimal.

The canonical bundle retains ten base files (9,159,216 bytes) and one
937,929-byte native batch proof. Global proof files are mandatory inputs to the
cold receiver. They are not recursively closed by the batch proof alone.

## Validation and reproduction

```sh
STWO_NATIVE_BATCH_DRIVER=1 STWO_REGISTER_COMPARE_ITERATIONS=61440 \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_register_custody_test_root.zig \
  -OReleaseFast --test-filter 'register custody complete comparison' \
  > driver-comparison.log 2>&1
python3 design/riscv-proving-stack/performance/native-batch-driver-results.py \
  driver-comparison.log
```

All **13 selected tests passed**. The new complete receiver matches all the
baseline global fields, with the old forest flag deliberately kept pending in
the new distinct result type. Fresh decoding and verification after destruction
of the driver owners succeeds. Changing the independently expected final RAM
root fails. Oppositely changing two physical recursive claims, while updating
the transport digest, fails with `OodsNotMatching`. No legacy forest metadata is
published by the replacement driver.

The parser rejects absent success markers, logged errors, mismatched workload
or baseline wall time, missing negative controls, invalid timing partitions,
zero peaks and incorrect root scope. Seven corrupted-log variants were checked.
Machine-readable data: [JSON](block-v6-native-batch-driver-m5-20261028.json) and
[CSV](block-v6-native-batch-driver-m5-20261028.csv), including the raw-log SHA256.

## Architectural implication

Recursion is still **62.1%** of this driver's canonical wall time. Removing all
collection and base proof work would therefore still leave about 20.5 seconds
before final verification. The small-fixture 17× recursive gain cannot be
extrapolated to this richer workload or multiplied by memory-area savings.

The next changes must reduce the statements and proof instances that recursion
verifies: joint native/companion commitments, independent component sizing,
and a proof-once event commitment bridge. Separately, investigate an explicit
whole-job I/O statement that does not require a persistent final VM RAM root.
That is a new protocol, not permission to skip current checkpoint checks.
Multi-batch coverage and recursive closure of every global family remain
required before publishing a standalone block-root claim.
