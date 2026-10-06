# Fixed iadd256 KMX RV32 experiment

This directory measures one 64-shot batch of the public `iadd256.kmx` circuit
from [`tanujkhattar/zkp_ecc`, branch `update_examples`](https://github.com/tanujkhattar/zkp_ecc/tree/update_examples),
commit `fc8dc785dee9aa1045e440ed42ba56942c458124`. The vendored file is
SHA-256 `eb85f1e61b235e2f598d910c93208b813f974aa02b43497b859dac02d4b2143d`.
It has two 256-qubit registers, 2,038 CX gates, 509 CCX gates, and 512 register
append operations. The fixed gate table is generated from that file at build
time. At runtime the guest hashes the supplied raw file and rejects any digest
other than the pinned value before applying the table.

The guest follows the upstream fuzzer's SHAKE256 stream over the raw KMX bytes:
each shot consumes a 32-byte little-endian target followed by a 32-byte
little-endian offset. For the selected batch, it simulates the repeated gates
on 64 bit-sliced shots and checks `(target + repetitions * offset) mod 2^256`,
offset preservation, and the fixed circuit's no-phase/no-ancilla invariants.
The CCX/CX counts establish the fixed circuit's per-shot resource limits.
The Python oracle additionally checks every gate and both registers and
produces the guest's input. Its first and last batch vectors and 4-repetition
simulation were compared with the original Rust `zkp_ecc_lib::Simulator` from
the same pinned upstream commit. Rust reported 521,728 Clifford and 130,304
non-Clifford gate executions for 64 shots at four repetitions, matching the
fixed table exactly.

Build and run from the repository root:

```sh
cd vectors/riscv_guests/iadd256_kmx
python3 -m unittest -v test_oracle.py
python3 oracle.py --repetitions 1 --total-shots 64 --batch 0 \
  --input-out /tmp/iadd256-r1-b0.bin
RUSTFLAGS='-C link-arg=-Tlinker.ld' cargo +nightly-2026-01-29 build \
  --release --target riscv32im-unknown-none-elf
cd ../../..
zig build riscv-bench -Doptimize=ReleaseFast
zig-out/bin/riscv-bench \
  --elf vectors/riscv_guests/iadd256_kmx/target/riscv32im-unknown-none-elf/release/iadd256_kmx \
  --input /tmp/iadd256-r1-b0.bin --max-steps 16000000 --secure --proof-identity
```

The binary input is seven little-endian `u32` values—repetitions, total
shots, zero-based batch, maximum qubits, maximum non-Clifford gates per shot,
maximum parsed operations, and raw KMX byte count—then the raw KMX bytes.
Successful output is the circuit hash, the six demand/selection words, and
the upstream success byte `42`. Source bytes and demands are *public* to the
current RISC-V proof statement. Build products and inputs are not committed.

## Measured first-batch ladder

These are **single observations**, not ranked or cross-machine comparisons.
Host: Apple M5 Max, 64 GiB RAM, macOS 26.7.1. Zig: 0.15.2 ReleaseFast.
Guest ELF SHA-256: `cdaec455f39459f7fec99428e5dcee4eca4670a981b90f1146e81cafa120391e`.
`prep` is the separate Python oracle check/input construction, around 0.05 s;
the CLI's execution/proving/verification times exclude that step. Host peak
is `/usr/bin/time -l` maximum resident set size. No Metal/CUDA acceleration
is involved. The functional profile is PoW 0 bits, 3 FRI queries and is not
a security-qualified benchmark; `secure` uses the repository's published
26-bit PoW, 70-query configuration. See `measurements.tsv` for proof identities.

| Repetitions | Profile | Steps | Prep s | Execute s | Prove s | Verify s | Total CLI s | Host peak GB |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | functional | 10,748,299 | 0.05 | 0.647 | 7.037 | 0.213 | 7.900 | 16.241 |
| 2 | functional | 10,849,703 | 0.05 | 0.635 | 7.171 | 0.213 | 8.021 | 16.353 |
| 4 | functional | 11,052,511 | 0.05 | 0.640 | 7.289 | 0.253 | 8.184 | 16.589 |
| 1 | secure | 10,748,299 | 0.05 | 0.638 | 7.581 | 0.256 | 8.497 | 16.244 |

Runtime noise is visible in the proof times; these observations support
geometry and cost composition, not a precise latency claim. Run-only checks
on the same ELF gave 13,891,823 steps at 32 repetitions, 15,919,903 at 52,
and 16,731,135 at 60. Sixty-one repetitions exceeds the current 16,777,216
step cap. After the roughly 10.65 million-step first-batch setup, each
repetition adds about 101,403 steps. The last batch (`batch=140` of 9,024
shots) exceeds the step cap even at one repetition when it regenerates its
SHAKE prefix from the circuit seed.

The first-batch secure proof was rerun after the Ethereum experiment cleanup
landed on main. It still verified and produced the same canonical proof
SHA-256 `b434b0d64d4164c76edf8d46526209a6832cd357cff531ce5c26c4046f200c46`.
This is a regression check of the retained typed RISC-V path; its timing is
not another controlled benchmark observation.

The last-batch cost is measurable with the execution-only segmented runner:
one repetition for batch 140 of 9,024 shots retired **83,892,949 RV32
instructions** across 21 segments of at most 4,194,304 steps. Its validated
journal SHA-256 is
`9d408dd394fe740fbfff08019ec7c0df78e99f3ad1ed340ef1851116bb5af804`.
Compared with 10,748,299 steps for batch 0, replaying the SHAKE prefix in
every batch is already untenable before the 8,000 repetitions begin.

The existing segmented runner did execute and capture 61 repetitions as
five leaf-local segments: four of 4,194,304 steps and a final 55,321-step
segment ending at the guest's halt flag, for 16,832,539 steps. Its validated
capture receipt has journal SHA-256
`f7717c6ab099df2d1f9a7088a1705018b7596687d51ce0d199c0290826adcdcb`
and reports `segment_statement_v2_admissible=false`. It explicitly says
`claim_boundary=execution-only-not-a-proof`: this is evidence of segmented
execution and continuity capture, **not** five verified segment proofs.

## What this does not yet prove

This is a real native proof of one complete fixed-circuit batch. It is **not**
the upstream 9,024-shot/8,000-repetition benchmark: no authenticated
cross-batch coverage, gate continuation, or recursive root exists here.
The upstream circuit is a *private* guest input and only its hash is public;
the current release-ABI RISC-V `--input` region publishes the KMX bytes. The
host-hint syscall path does not solve that: ECALL traces are execution-only
and rejected by the RISC-V proof admission path. A private initial-memory
witness with proof-bound circuit hash is required for statement parity.

The next architecture must prove (1) one exact raw-circuit commitment and
parsed program, (2) a sequential SHAKE stream whose state checkpoints bind
every target/offset batch without replaying an ever-longer prefix, (3)
repetition ranges whose before/after packed qubit-state commitments match,
and (4) exact coverage of all 141 batches and 8,000 repetitions in a final
verified root. The existing segmented-execution journal explicitly labels
itself `execution-only-not-a-proof`; its capture receipts cannot replace
native segment proofs and detached verification. The current 1/2/4/8-segment
recursion fixtures also do not constitute a generic 141-batch reduction.

This experiment shows that RV64 is not logically needed to express the
circuit, but a generic RV32 execution proof pays large fixed costs for
SHA-256, SHAKE, input handling, and millions of ordinary instructions. A
dedicated bit-sliced CX/CCX AIR or precompile should be compared against
continuing with generic RV32 before extrapolating a full benchmark time.
