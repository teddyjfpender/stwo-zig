# OP Mainnet CPU critical path

The comparison uses the same canonical GLV guest, block 121057303 input and
1,048,575-step geometry across the four producers in the table. The selected profile is
`conjectured128_b2_q108_p20_fold4`. All 15 binary proof and sidecar hashes
match. Both bundles passed independent reception and exact corruption
rejections. The earlier overlapping build trial was killed and is excluded.

| Producer | Wall | Native proof stage | Lookup GKR | Peak RSS |
|---|---:|---:|---:|---:|
| d366924 control | 256.543 s | 224.119 s | 77.258 s | 4.00 GiB |
| Wide GKR source tiles | 243.124 s | 209.945 s | 58.543 s | 3.99 GiB |
| Wide tiles, two four-worker lanes | 208.376 s | 181.974 s | — | 4.80 GiB |
| Tuned CPU kernels, same two lanes | 172.102 s | 149.793 s | — | 4.88 GiB |

Cold committed receiver wall was 52.156 s in the control, including 34.020 s
of native source keys and 11.041 s of FIXED authority. The wide-tile run
selected the existing identity-only receiver and took 28.215 s. These cold
runs measure different setup policies, with one sample per policy. The
two-lane run selected identity-only setup and took 24.735 s cold. Its proof
verification took 1.373 s. The matched tuned run took 23.593 s cold,
including 0.429 s of proof checks. Both corruption trials passed again.
[Two-lane run](cpu-two-lane.json) · [Matched tuned run](cpu-matched-final.json)

The verifier-only resident process received the two durable copies twice in
30.597 s total, peaking at 2.43 GiB. The first request spent 25.125 s in setup
and 1.178 s in verification. The subsequent requests took 1.367, 1.238 and
1.356 s including loading. They performed zero new source validations. The
warm path rejected a modified proof at transport admission and rejected it
again after recomputing its outer digest.

With four physical verification workers the same warm requests took
0.583, 0.489 and 0.485 s including loading. Their proof checks took
0.421–0.427 s and still reject both mutations. The cold parallel request
spent 29.985 s independently deriving setup while a separate compile was
running. [Receiver comparison](receiver-parallel.json)

The borrowed BN254 Miller loop candidate completed all six OP Mainnet
execution and Unicorn comparisons. On 121065789 it reduced 625,036,497
instructions to 621,225,921 and service RAM word transitions from 40,325,354
to 37,597,627. This checkpoint has execution evidence for that heavy block.
Its complete CPU proof is still open.

The exact ELF and input hashes are in [checkpoint.json](checkpoint.json).
The CPU execution bundles use native STARKs without SNARK wrapping.

## Checked pairing advice

The optional `canonical-glv-hinted` guest independently matched the execution
oracle on all six cases. Block 121065789 used 458,997,937 instructions with
747,798 Fp2 calls and 32,252,287 service RAM word transitions. Against the
borrowed-loop guest, this saves 26.11% of instructions and 19.44% of Fp2 calls.
The 84 hints add 80,988 bytes to the pinned block input. Host generation has a
separate wall receipt and the guest checks the residue identity itself.

[Hint generation and execution receipts](pairing-hints.json) ·
[Field identity and reproduction](../../../opstack/PRECOMPILES.md#optional-positive-pairing-advice)

The exact Miller factor cache keeps the same hinted input bytes on all six
cases. Block 121065789 falls further to 425,529,933 instructions, 678,888
Fp2 calls and 29,341,602 service RAM word transitions. All six runs match
the independent oracle. [Factor cache receipts](pairing-factors.json)

## CPU kernel validation

The tuned runner completed block 120794432 (796,226 instructions) with one CPU
proof and two service proofs. Producer wall was 64.585 s and independent cold
reception was 9.828 s, including 0.123 s of proof verification. The run
overlapped compilation and both corruption checks passed.
The 2,097,151-step plan for 121057303 derives three CPU and seven service
proofs with 30.240 billion MAIN+INTERACTION bits. Its first producer attempt
overlapped compilation and was killed. [Kernel run receipts](cpu-kernels.json)

## Bounded scratch capture

With scratch capture, block 120794432 completed in 37.657 s producer wall
and 7.422 s fresh receiver wall. All five binary proof and sidecar hashes
match its in-memory run. The smaller in-memory run overlapped compilation,
so this is a byte-parity check with timings from separate host conditions.
The scratch path matches the complete in-memory plan for block 121057303.
The heavy block exhausted its 40 GiB backing cap after 955.248 s and exited
with a controlled allocation error. [Capacity receipts](capture-backing.json)

The census planner on block 121057303 reproduced all CPU and service
declarations, source bounds, final PC, memory words and 32,232,733,600
MAIN+INTERACTION bits. Peak RSS was 1.323 GiB versus 1.731 GiB for the
retained planner. The census run overlapped tests.
[Exact plan comparison](capture-census.json)

The complete census for heavy block 121065789 took 251.246 s at 2.040 GiB
peak RSS. It covered 425,529,933 retired instructions, 539,388 public RAM
words and 126 planned proofs across 102 CPU and 24 service declarations.
The padded MAIN and INTERACTION trace contains 1,657,146,610,432 bits.
MAIN alone corresponds to about 122.5 GiB at four bytes per cell, before
coefficient parking and PCS. The result qualifies capture and planning.
[Heavy mainnet plan](heavy-mainnet-plan.json)
