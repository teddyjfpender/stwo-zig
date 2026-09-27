# Native local-zero GPU inventory

The source-only native migration now reaches the existing base-field and LogUp
GPU compilers through the actual `SemanticComponent` and
`OpcodeLookupComponent` capability exporters. It does not introduce a second
AIR or independently transcribed GPU equations.

The old local-zero program IDs used namespaces3/4, which collided with retained
hash-provider programs. The runtime base program cache indexes by `program_id`.
The new native recipes now use7/8, while old native1/2 and retained providers3–6
keep their identities. The shared inventory rejects duplicate IDs within each
runtime program family.

`native_polynomial_inventory_v1.zig` owns the exported programs, their cleanup
and the complete legacy/candidate/local-zero inventory. The original production
Metal source parity test and the focused offline exporter use this same owner.
The source, native shader manifest entries and generated Objective-C bootstrap
are derived together, preserving unrelated framework kernels.

There are95 program entries and94 executable kernels:17 new direct recipes and
17 new lookup recipes. Family16's lookup DAG is unchanged by local-zero custody
and shares the existing content-addressed executable. Each entry is validated
before executable deduplication; a forged authority cannot hide behind an
already emitted kernel.

The focused ReleaseFast CPU gate passes6 checks (4 named admission checks and2
import checks): every native family's exact old/new capability is admitted;
shader/source/bootstrap inventories agree; duplicate runtime IDs are rejected;
altered local-zero DAGs lose admission; repeated V2 executable identities still
validate the second authority. This gate executes no guest, STARK or device.

Regeneration is independent of the full prover test suite:

```sh
python3 scripts/riscv_native_polynomial_aot.py \
  --output NEW_ARTIFACT_DIRECTORY --compile-metal --update-source
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py \
  --root src/riscv_native_polynomial_aot_test_root.zig 'native GPU inventory:'
```

Evidence is retained in `cpu-performance-gates-v1/native-x0-polynomial-inventory-v1.log`
and the `native-x0-polynomial-metal-aot-*` source/binary manifests. The finalv2
artifact uses Metal3.1, safe math and warnings as errors, and syntax-checks the
actual Objective-C runtime after publishing the source inventory.

This qualifies export, offline compilation and cold executable admission.
Canonical local-zero activation remains disabled. It does not qualify GPU
execution, resident scheduling, complete proof verification, throughput or
end-to-end block performance. Segment proving remains stopped.
