# iadd256 circuit benchmark contract

This experiment uses only the public `update_examples` branch of
[`tanujkhattar/zkp_ecc`](https://github.com/tanujkhattar/zkp_ecc/tree/update_examples),
pinned at commit `fc8dc785dee9aa1045e440ed42ba56942c458124`. The public
`docs/example_data/iadd256.kmx` bytes have SHA-256
`eb85f1e61b235e2f598d910c93208b813f974aa02b43497b859dac02d4b2143d`.
This is a source identity, not a proof result.

## Statement that every route must prove

The reference is
`docs/example_tools/example_zkp_fuzzer/example_zkp_fuzzer.rs` at that commit.
It parses the private KMX bytes, hashes the raw bytes with SHA-256, seeds
SHAKE256 with the same bytes, and draws a 32-byte little-endian target and
offset for every shot. It applies the parsed circuit `num_repetitions` times
to 64 bit-sliced shots per batch. For every shot it checks the target against
`target + num_repetitions * offset (mod 2^bit_width)`, checks the offset is
unchanged, and rejects phase or ancillary garbage. It checks the circuit
shape, operation/qubit bounds, and sampled non-Clifford bound, then commits
the circuit hash, requested limits and a success byte of 42.

The fixture parses as 3,061 operations: 512 register appends, two register
declarations, 2,038 CX and 509 CCX. At 9,024 shots there are exactly 141
64-shot batches. At 8,000 repetitions, each batch executes 20,376,000
CX/CCX operations; all batches together execute 2,873,016,000. This count
is a workload descriptor, not an instruction count, trace-row count or proof
time. The upstream simulator also visits register declarations each repeat.

The exact upstream ELF is ELF64 RISC-V. An RV32 or Cairo implementation may
be compared on the same *statement* if it preserves the input derivation,
parser acceptance, gate order, checks and public outputs. Executing the ELF
byte for byte is a separate RV64 compatibility objective.

## Splitting and aggregation

A batch leaf must bind its circuit hash, limits, repetition count, batch index,
valid-shot count, SHAKE-derived target/offset inputs, final state, checks and
operation counts. The 141 leaves may be proved independently. A root must
verify every required leaf exactly once in order, authenticate the common
circuit/parameters and SHAKE stream, combine counts with checked integer
arithmetic, and enforce all global bounds. Host-generated inputs or host-summed
counts cannot substitute for proof of those relations. A source-generation
proof or an equivalent in-circuit SHAKE check is needed if leaves consume
precomputed batch inputs.

Repetitions within a batch may be segmented. Each transition must bind the
full live state and exact circuit/repetition position; the next segment must
consume the previous final state. No synthetic empty or padded leaf may cover
a missing batch, and the final batch size must be checked.

## Measurement rules

For RV32 guest, Cairo guest and gate-specific AIR, record separately:

| Evidence | Required content |
| --- | --- |
| Correctness | Differential output against the pinned reference, malformed-input rejections, independent verification of every claimed proof and the final root |
| Scope | Exact fixture/source digest, repetitions, shots, security profile, proof format, and whether SHAKE/parse/global checks are inside the proof |
| Performance | Input preparation, execution/witness, leaf proving, wrapping, folding, root verification and full input-to-root time |
| Capacity | Trace rows/components, peak host RSS, peak whole-device memory, worker count and hardware |

Start with one batch at one repetition, then increase repetitions and batch
count. A simulator, geometry estimate, or unverified proof is diagnostic only.
Cross-route speed claims require the same statement, comparable soundness,
honest timing boundaries and independently verified roots. Proof stages that
are not yet implemented must remain explicit gaps in the comparison.
