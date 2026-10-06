# Direct CX/CCX AIR experiment

This is a focused proof route for the public `iadd256.kmx` fixture. It proves one application of the circuit to the first 64 distinct SHAKE-derived shots. It does not yet prove the benchmark's 8,000 applications or all 9,024 shots, and its timing is not a full QEC benchmark result.

## Proven statement

The pinned fixture has 256 bits in each of two registers, 2,038 CX gates, and 509 CCX gates. For each of the first 64 consecutive 64-byte SHAKE256 outputs of the exact fixture bytes, the prover commits to 512 initial qubit bits and one output bit per gate. The AIR checks each gate's Boolean transition and that all 512 final bits equal the public target plus offset modulo 2^256, with the offset register unchanged. The same 64 physical rows represent 64 distinct shots; they are not repeated copies of one shot.

The verifier independently parses the public fixture, checks its SHA-256 digest and gate count against the proof statement, derives the 64 challenge pairs with SHAKE256, and recomputes the fixed input/output-column Merkle root. A changed challenge fails the fixed-root check. The gate topology is baked into the verifier-derived AIR. SHAKE execution, fixture parsing, and SHA-256 are host checks; they are **not** constraints within this AIR. The output bits are public through the SHAKE-derived challenge table and fixed-column root, rather than a separate proof-output object. The circuit is public, so this is a fixed-circuit statement; it does not establish a generic private-circuit parser or source proof.

The proof uses Stwo's Blake2s-prefixed commitment/channel profile, 70 FRI queries and 26 proof-of-work bits. Cubic CCX/XOR constraints need composition log degree `log_rows + 2` and a two-chunk composition split. With a one-chunk split, different-height trace columns are lifted at OODS and the prover correctly rejects the nonconstant 64-shot witness as inconsistent. The split-two proof decodes and verifies in a fresh verifier. The verifier also rejects a changed SHAKE challenge through the recomputed fixed root.

## Focused measurement

One ReleaseFast run on an Apple M5 Max, 64 GiB host, with a CPU Stwo backend:

| Quantity | First 64 shots, one repetition |
| --- | ---: |
| Gate-output columns | 2,547 |
| Public fixed columns | 1,024 |
| Trace rows | 64 |
| Total trace field cells | 228,544 |
| Proving | 3.124 s |
| Fresh decode and verification | 0.153 s |
| JSON proof wire | 2,661,981 bytes |
| Whole test process maximum RSS | 17,956,864 bytes |

RSS is the maximum of the focused nine-test executable, not an isolated proof-only allocation counter. The test process includes the one-shot diagnostic and small parser/AIR tests; it excludes compiler memory. The run can be repeated with `zig build test-qec-gate-static -Doptimize=ReleaseFast`. Timing numbers are observations, not a distribution. The one-shot diagnostic in that command is a separate, smaller statement and should not be compared with 64-shot Cairo or RV32 proofs.

## Scaling route

The wide static circuit is a first qualification rung. Unrolling 8,000 repetitions into columns would need `512 + 2,547 * 8,000 = 20,376,512` trace columns, before proving all 141 groups of 64 shots. That is not a practical architecture.

A narrow gate-row AIR should use one logical row per active gate per repetition and 64 shot lanes across a bounded column set. Each row identifies `(repetition, gate_index)` from an authenticated public gate ROM and checks the CX/CCX relation in every lane. Input controls and the previous target value come from the most recent write to their qubit. This requires a sparse read/write argument: emit fixed predecessor-edge accesses or time-stamped `(shot, qubit, value)` accesses, sort or permute them, and check that each read matches the preceding write. The fixed gate ROM must be recomputed by the verifier from the hash-pinned fixture or committed as authenticated preprocessed data. Trusting a host-supplied gate type or predecessor index would change the proof statement.

There are 20,376,000 active gate rows per 64-shot batch at 8,000 repetitions, padded to 2^25 for a monolithic gate table. The fixture entails `2,038 * 3 + 509 * 4 = 8,150` control/target read-write accesses per repetition, or 65.2 million access rows per 64-shot batch if 64 shots are carried as lanes. The access argument, rather than the raw gate table, is likely to set the segment size. A 1,024-repetition segment has 2,608,128 active gate rows, padded to 2^22, and 8,345,600 access events before padding. Eight such segments per batch and 141 batches imply 1,128 leaves, followed by recursive aggregation. These are geometry estimates only; no narrow gate-row proof or full tree has been implemented or timed.

Every segment boundary must bind all 512 qubit bits for all 64 shots (32,768 bits) as public or recursively verified state, plus its repetition interval, circuit identity, and challenge-batch identity. The final segment checks the same target-plus-repetitions-times-offset relation and unchanged offset. The first and last 64-shot batches must be linked to the exact SHAKE stream. Recomputing the SHAKE prefix within every leaf is not viable for late batches; authenticated stream checkpoints or a separate source proof are needed. Proofs should then be aggregated into one root without silently replacing execution with a closed-form arithmetic shortcut.

A separate fixed-fixture precompile is possible: the included Z3 diagnostic exhaustively checks the one-application Boolean circuit against 256-bit addition and unchanged offset. Induction then gives the result after any repetition count. That is a stronger fixed-fixture theorem but **skips the repeated gate execution** measured by the SP1 benchmark. It needs its own reviewed certificate, one-time setup accounting, and benchmark lane; it cannot be presented as like-for-like execution proving.
