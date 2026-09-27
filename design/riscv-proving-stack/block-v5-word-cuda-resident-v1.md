# Canonical word-memory CUDA resident bridge v1

Six device-free runtime contract checks pass, and concrete actual NativeSession
wrappers compile to an object without CUDA linking or execution. The complete
11-kernel source catalog was exported and staged through production product
validation; four source/product admission fixtures pass. NVCC compilation, binary
embedding and device execution remain unqualified. Segment proving remains stopped.

`src/backends/cuda/runtime/secure_polynomial_v1.zig` uses the existing strict-AOT
`NativeSession.launchKernel` API and actual context allocation-generation checks.
It neither JITs nor loads arbitrary modules. All device allocations are supplied
by the proof owner's charged arena. Plans retain bounded CPU schema and ingress
metadata, never whole trace/LDE arrays. Plan and witness metadata must stay at a
stable address until ingress transfers are joined; the owner must join or abort
before releasing plans, catalog, arena, or input buffers.

## API and admission

`aot/secure_polynomial_registry_v1.Catalog.read` accepts bounded manifest bytes,
an independent SHA-256, independently derived typed programs, expected SM, and
limits. The versioned manifest enumerates exact source identities, names, ABI
schemas, cache keys, cubin lengths and SHA-256 pins. Extra, duplicate, missing,
wrong-SM and mismatched schema entries reject. Source identities are recomputed
from the current typed program/emitter/field implementation; no recorded catalog
identity is hardcoded. Helpers authenticate their own exact source.

`secure_polynomial_resident_codegen_v1.generateLibrary` emits the existing typed
CUDA DAG followed by resident helper kernels. An offline product builder must
compile it and add authenticated entries to the existing `stwo_aot_lookup`
embedded pack. This registration step is not implemented by runtime loading.
CUDA ABI schema IDs 23–29 are append-only. `Kernel.expected_cubin_sha256` and
`expected_cubin_bytes` additionally match both expected and observed receipt
identities, including function-cache hits; legacy kernels omit these fields.

The owner follows this sequence:

1. Create `Plan` from the actual typed program and trace geometry. Equation plans
   also bind exact coefficient powers. Create one `RangeTablePlan` per shared
   range challenge and `WitnessPlan` from independently admitted claim words.
2. Preallocate all metadata, trace, output, status, inverse table, totals and scan
   scratch in the existing arena. `Geometry.fractions` reports exact scratch
   extents and charged output/scratch/table/status bytes. Input arenas are charged
   by their owner separately. Explicit resident/metadata/log caps apply.
3. During ingress, call `ProofStatus.begin` once, then upload plan/table/witness
   metadata. Never clear status between dispatches. Uploaded metadata bindings
   include exact address, owner, allocation generation, extent and invocation.
4. At trace generation, dispatch word or range witness. At constraint evaluation,
   generate the inverse table once, launch raw fractions, then `scanAndCenter`;
   launch equations on the correctly expanded fixed/main/interaction arenas.
5. Keep outputs `Pending`. At proof assembly, `ProofStatus.check` reads exactly
   one status word and synchronizes, then produces a `Completion` only for zero
   status. `Completion.admit` checks the status lifetime and live allocations;
   it may admit all pending outputs in the same proof. `complete` is a one-output
   convenience wrapper. Status reuse invalidates earlier completions. A pole,
   noncanonical field value, invalid witness or unknown bit is terminal failure,
   even if the generated columns contain zeros. No dispatch is permitted after
   successful or failed completion. Claims may then be read via `readTotals` at
   proof assembly. This completion is an execution check, not a STARK receipt.

## Implemented kernels

The typed equations preserve canonical fixed12/main27/interaction68 word AIR and
fixed1/main1/interaction8 range16 AIR. Raw LogUp output has 17 word planes or two
provider planes. Generic active denominators reject poles; all range requests
use one challenge-bound 65,536-entry secure inverse table and pole bitmap, rather
than recomputing range inverses per row. Unused pole entries do not fail a proof;
active requests do.

A 256-thread inclusive block scan operates in logical committed-row order. Its
block totals are recursively scanned in bounded scratch levels; carry dispatches
propagate them downward. A separate totals dispatch precedes mean centering, so
there is no cross-block read/write race on the tail. Every plane has its own raw
secure total and mean. Scratch/outputs remain resident. The word witness writes
all 39 fixed/main columns directly from six-word sorted records and an independent
25-word claim, preserving high clocks, limbs, gap carries, adjacency, endpoints,
and padding. Range witness derives the fixed values and multiplicities.

## Qualification and remaining integration

`src/block_v5_word_cuda_resident_test_root.zig` contains six CPU-only admission,
geometry, source, dispatch and failure-boundary fixtures. Its host dispatch adapter
checks contracts without executing kernels; it cannot establish device arithmetic
parity or performance. The root agent owns running this qualification.

Offline CUDA compilation, pack embedding and device parity still need explicit
qualification. A full resident proof engine also needs the means/totals to feed
resident transcript and dynamic claim-parameter preparation before equation/PCS
execution. The current context correctly forbids a host download of those values
mid-proof; this bridge does not evade that restriction. Final PCS/quotient proof
assembly must enforce completion before consuming/publishing success. The native,
program, caller/precompile, auxiliary sidecar and recursive AIR families are not
covered by these word/range kernels. No full GPU proof or speed claim is made.

The concrete object-only owner gate is
`src/block_v5_word_cuda_runtime_codegen.zig`. Its retained wrappers instantiate
all generic dispatch and completion APIs against the actual `NativeSession` and
`Context`; the exported address-retaining function makes no runtime calls.

`scripts/cuda_build_lib/secure_product.py` supplies `stage_secure_product` for
source-only product admission. It takes the independent exported catalog SHA,
trusted field header and independent header SHA, destination, and explicit entry,
source and aggregate byte caps. It publishes only a completely validated source
set in the existing AOT manifest format. `aot_identity.py` validates the new typed
identity scheme against the pinned catalog, actual signatures, field/source
hashes, exact ABI and little-endian cache keys. `ABI_SCHEMAS` includes IDs 23–29.
The existing `compile_aot`, pack builder and carrier remain the only binary
compilation/`stwo_aot_lookup` path. No parallel standalone lookup is introduced.
The adapter retains complete translation units per entry to fit the existing
one-source-per-entry builder contract; those copies are explicitly charged to its
aggregate source cap. Binary/module deduplication is not claimed.

A product owner still has to independently pin/select the staged set in its
product declaration before compiling it. The tracked RISC-V availability remains
unchanged. `scripts/tests/test_cuda_secure_product.py` adds four CPU-only source,
ABI, cap, digest and existing-carrier fixtures; they use fake bytes solely to test
pack framing, with no claim that those bytes are CUDA binaries. All four fixtures pass on CPU. Actual exported source admission also passes;
this is stronger source evidence than the synthetic framing fixture but still
provides no CUDA binary or hardware evidence.

Current source and NativeSession object receipts are retained in
[`word-gpu-aot-cuda-source-v1`](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/word-gpu-aot-cuda-source-v1/).
Its11-entry source set passes the same production selector used by the offline
builder and is retained in
[`word-gpu-aot-cuda-product-v1`](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/word-gpu-aot-cuda-product-v1/).
Neither directory contains a qualified CUDA binary. Canonical two-event RAM
requires its own new typed kernel ABI; these word-v4 kernels cannot be relabeled.
