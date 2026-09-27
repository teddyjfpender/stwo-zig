# Word-memory v4 GPU kernel bridge

This is source engineering for the canonical word-memory AIR, not a hardware
qualification or a GPU speed result. Execution-segment proofs and block runs
remain stopped. Seven CPU parity/admission tests pass. The generated Metal
library and actual Zig/Objective-C runtime bridge compile; no GPU kernel or
proof has been executed.

`block_v5_word_gpu_program_v1` exports the existing typed word `Algebra` and
interaction `Algebra` to a bounded secure-field DAG. The export covers fixed12,
main27, interaction68, all 46 direct and 17 interaction equations, and both
range16 equations. The range16 scalar and packed evaluators share the extracted
`block_v5_range16_algebra_v1` helper. Previous main openings remain exactly
columns 2–8 and 25–26; all interaction coordinates have current/previous
openings. Public endpoint values and challenges are dynamic invocation slots,
while source bytes, protocol ABI, input routing and equations authenticate the
executable schema. This introduces no new proof protocol or receipt authority.

The Metal code generator lowers genuine QM31 equations to additive composition
kernels. `EquationPlan` keeps a cold schema snapshot and a prepared AOT pipeline;
its `evaluate` method takes existing resident fixed/main/interaction arenas,
coefficient powers, and a separate resident output. It computes the same
quotient-coset inverses and shifted circle rows as the existing polynomial
engine. A dedicated bridge validates actual `MTLBuffer` ownership and extents;
it does not reinterpret a resident buffer as a committed-tree object.

`FractionPlan.generate` computes the 17 word raw fraction/count planes (or two
range planes), runs the existing independent block scans, then a new per-plane
mean-removal kernel. Device totals remain in the output tail. The returned
resident owner exposes columns and totals and must outlive their subsequent
commitment. Device status rejects active denominator poles and noncanonical
range inputs; zero-weight requests skip unused poles exactly as the CPU path.

Range requests use an explicit `range_fraction` instruction. One
`RangeInverseTable.init` generates the complete 65,536-value resident inverse
and pole table for the sealed arity-one range challenge. Every requester and
provider invocation checks that exact challenge and reuses the table. This
avoids per-row QM31 inversions in all nine range planes. The table retains
1,310,720 bytes; derivation temporarily adds 16 metadata bytes. The eight
transition/link/initial/endpoint terms still use direct device inversions. A
future batched inversion optimization for those terms is a separate gap.

`word_memory_witness_v4.metal` generates fixed12/main27 column-major committed
rows directly from resident six-word sorted transitions. It retains full u32
addresses/values and u64 clocks, reconstructs exact radix-65536 gaps/carries,
checks shard endpoints and adjacency, and zero-fills padding. The companion
range witness kernel emits fixed values and multiplicities. Typed
`block_v5_word_gpu_witness_v1.claimWords` supplies independently admitted public
claim metadata; raw records cannot choose this policy. Planned roots, census
and provider counts still require the existing fresh receiver checks.

Production loading is AOT-only. `installAot` accepts an independently trusted
metallib SHA and a roster of independently exported programs, caps the binary
at 128 MiB and the program roster at 16 entries, resolves exact names, and
installs all pipelines only after successful admission. It never compiles
source or replaces a live dynamic executable. The existing base Metal profile
identity does not describe this sidecar: production reports must additionally
record its binary SHA and schema/codegen identities.

Practical integration order:

1. Export typed word/range programs after the common seal has fixed challenges;
   build and independently pin the generated AOT sidecar outside proof runtime.
2. Install that sidecar once on an owner-serialized Metal runtime. Derive one
   range inverse table and retain it across all matching requester/provider
   invocations.
3. Generate fixed/main columns directly or use existing proof-owned resident
   columns. Run the fraction/scan/mean path, match totals to independent census,
   and commit the resulting interaction columns through the existing PCS.
4. Prepare/evaluate equation plans against resident LDE arenas, then use the
   existing PCS/OODS/FRI pipeline and unchanged fresh typed verifier.
5. Join every synchronous command before releasing borrowed arenas; deinit the
   result, plans and shared table explicitly. Incremental allocation caps count
   output/scratch/metadata; existing input arenas remain charged to their owner.

CUDA uses the same instruction emitter and existing CUDA QM31 field primitives
to produce actual equation, raw-fraction and shared inverse-table kernels.
CUDA resident invocation, hierarchical scan/mean and direct witness dispatch
are implemented and pass device-free contract checks. Actual NativeSession
wrappers compile; complete source export passes production offline-product
admission. NVCC compilation/embedding and device parity remain unqualified. The full word proof engine
also needs to select the new resident plans rather than the current CPU
quotient adapter; the CPU block driver is unchanged. Device parity, generated
metallib/PTX compilation, resident PCS integration and full fresh proof gates
are required before claiming GPU family coverage.

The CPU-only roots are `src/frontends/riscv/block_v5_word_gpu_program_test_root.zig`
and `src/block_v5_word_gpu_codegen_test_root.zig`. They cover every typed OOD
equation, exact CPU mean-centered fraction buses including padding/high u64
clocks, range-provider/table parity, active/unused poles, wide public metadata,
dynamic executable reuse, source authentication, routing/cap rejection and
foreign-builder rejection. They contain no STARK proving or GPU session setup.

## Offline compilation evidence

`scripts/riscv_word_gpu_aot.py --target metal --compile-metal
--check-metal-runtime --output <new-artifact-directory>` exports four canonical
word/range equation and fraction programs, compiles a real metallib, checks the
actual runtime bridge, and publishes source and binary SHA receipts atomically.
It performs no GPU execution, runtime JIT or STARK proving.

Qualified four-program output snapshot is
[`word-gpu-aot-metal-v2`](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/word-gpu-aot-metal-v2/).
Global first/last activation is a dynamic public parameter, so one compiled
schema covers terminal and interior shards, different capacities, and register
or RAM custody. CPU arbitrary-point checks compare all63 word equations against
the typed evaluator across those geometries. Earlier v1 artifacts precede this
fix and are marked superseded. Resident execution, transcript/PCS integration
and a fresh independently verified GPU proof remain outstanding.

Canonical two-event RAM kernel export and resident quotient integration are now
being implemented. Their new typed ABI and source identities require fresh offline
artifacts and separate qualification; historic word-v4 snapshots cannot establish
coverage of the lane protocol.
