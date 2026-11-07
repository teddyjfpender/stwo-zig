# OP Mainnet CPU critical path

The comparison uses the same canonical GLV guest, block 121057303 input and
1,048,575-step geometry across the first three producers. The selected profile is
`conjectured128_b2_q108_p20_fold4`. All 15 binary proof and sidecar hashes
match. Both bundles passed independent reception and exact corruption
rejections. The earlier overlapping build trial was killed and is excluded.

| Producer | Wall | Native proof stage | Lookup GKR | Peak RSS |
|---|---:|---:|---:|---:|
| d366924 control | 256.543 s | 224.119 s | 77.258 s | 4.00 GiB |
| Wide GKR source tiles | 243.124 s | 209.945 s | 58.543 s | 3.99 GiB |
| Wide tiles, two four-worker lanes | 208.376 s | 181.974 s | — | 4.80 GiB |

Cold committed receiver wall was 52.156 s in the control, including 34.020 s
of native source keys and 11.041 s of FIXED authority. The wide-tile run
selected the existing identity-only receiver and took 28.215 s. These cold
runs measure different setup policies, with one sample per policy. The
two-lane run selected identity-only setup and took 24.735 s cold. Its proof
verification took 1.373 s. [Two-lane run](cpu-two-lane.json)

The verifier-only resident process received the two durable copies twice in
30.597 s total, peaking at 2.43 GiB. The first request spent 25.125 s in setup
and 1.178 s in verification. The subsequent requests took 1.367, 1.238 and
1.356 s including loading. They performed zero new source validations. The
warm path rejected a modified proof at transport admission and rejected it
again after recomputing its outer digest.

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
