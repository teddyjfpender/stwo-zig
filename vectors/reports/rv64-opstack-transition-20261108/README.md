# OP Mainnet transition, CUDA and settlement checkpoint

Native Kona and the RV64 guest independently accepted OP Mainnet
159257841 → 159257842 from Ethereum anchor 26367973. The guest output
binds the anchor, both output roots, L1 origin, derived payload and
computed L2 hash. A separately packed execution input produced the
matching `OP` output. The host rejected changed anchor, output root,
blob bytes and a swapped KZG proof. The retained witness, build commands
and exact output are in the [transition runbook](../../../opstack/TRANSITION.md)
and [receipt](../../../opstack/transition-159257842-receipt.json).

| Replay variant | Input bytes | Retired instructions |
|---|---:|---:|
| Single sidecar verification | 21,530,433 | 7,760,207,964 |
| Whole-witness KZG batch | 21,530,433 | 5,185,015,337 |
| Batch and admitted SHA | 21,530,433 | 4,515,634,562 |
| Pruned witness, compressed | 18,871,913 | 4,317,643,221 |
| Same pruned body, uncompressed | 33,312,954 | 3,754,949,463 |
| Uncompressed body and direct canonical scalar decode | 33,312,954 | 3,250,596,756 |

All rows publish the same anchored `OD` output. The last row is 58.1%
below the original run. The two uncompressed runs also differ in shared
runtime source snapshots, so their delta does not isolate the scalar
decoder. The larger uncompressed input trades initial memory for guest
instructions. No proving-time improvement is inferred. The last row
needs at least 776 CPU shards at the 22-bit trace limit before services,
above the current 256-proof limit. The profile still needs a sound
segmented transition route or much lower guest work to prove this case.
The [raw replay receipt](raw-replay.json) pins both raw-input runs, and the
retained `OP-Mainnet-159257842-Optimized-Replay.zip` carries the fastest
run's exact witness, ELF and receipt.

### Single-fraction KZG evaluation

The follow-up [receipt](kzg-fraction-replay.json) compares the archived
direct-scalar guest and the single-fraction guest on the same pinned
uncompressed witness and RV64 runner. Native Kona and both guests produce
the identical anchored output. The single-fraction guest retires
**3,071,915,334** instructions, down **5.50%** from 3,250,596,756. Both
runs have 9,672,285 service RAM word transitions.

The evaluator accumulates the barycentric terms as one field fraction
and skips zero terms while still decoding and validating every scalar.
The KZG transcript, subgroup checks, and batch pairing equation stay
the same. The c-kzg vectors pass, and native replay rejects changes to
the anchor, next root, consumed blob data, and KZG proof.

The new native CPU entry point checks the exact pinned `OD` statement.
It records a blocked attempt before capture: the replay needs at least
733 CPU proofs at the current trace limit, with service proofs still
to account for. The maximum even with all 256 slots assigned to CPU
work is 1,073,741,568 instructions. A segmented solution needs an
authenticated continuity relation across PC, registers, clocks, RAM
and service boundaries, plus a composed soundness analysis. The
current candidate caps remain in force.

The [batch profile](rv64-batch-hotspots.json) attributes the exact
5.185B-instruction run to ELF symbols. Brotli accounts for about 1.07B
instructions across its two largest symbols. Software SHA compression
accounts for 701M before enabling the admitted SHA service. The profile
also identifies BLS scalar decoding, field multiplication and memory
copying as large costs.

A separate OP Mainnet 120794432 native execution bundle completed in
58.902 s at 2.722 GiB peak RSS and was accepted by a fresh receiver in
5.776 s. It contains one CPU and two service proofs and rejects both
transport corruption and proof corruption after rehashing the manifest.
Its recursive wrap was killed during the first leaf graph. The execution
bundle, exact failure and synthetic application-fold status are recorded
in the [native and recursion report](../rv64-opstack-recursion-20261108/).
The [receiver-side join](../../../opstack/RECURSIVE.md) pins both proof
profiles and both expected outputs. An independently accepted complete
recursive transition root is still open.

The CUDA path merges integration tip `4a4d01bd5999bd6489fe71062c9e46ccdbcd73bb`.
The native and combined CUDA semantic checks passed. The [CUDA runbook](../../../opstack/README.md#full-block-cuda-benchmark)
requires real kernel activity and fresh CPU acceptance. Its cold and warm
mode requires byte-identical proof bundles. No CUDA host was available for
this run. Block 121065789 has 102 planned CPU scopes at the recorded geometry,
above the one-device scope cap of 64. Device memory fit and physical
throughput still need measurement.

Solidity replayed every FRI layer for each worker in the accepted 120794432
bundle, using native-captured DEEP values. It independently recomputed a
DEEP value from authenticated trace rows for one query per worker. The
checked-in truth-1 FRI regression covers 74 queries and two layers at
59,593,990 gas on Shanghai Anvil. The complete joined PCS replay derives
those queries, authenticates the trace openings, computes their DEEP
quotients and verifies both FRI layers. It accepted in an elevated local
call with estimated gas of 1,724,143,850. This PCS replay takes its prefix
and sample layout from the native capture. The standalone RV64 initial
AIR evaluator and checkpoint transport parity tests cover additional
relations separately. See the [settlement runbook](../../../settlement/README.md).

The measured native settlement components exceed the transaction cap on
real worker shapes. A compact recursive STARK and a complete verifier
owned by the checkpoint remain open. The engineering proof profile
retains `security_qualified=false`. None of the measured paths adds a
SNARK wrapper.
