# Private circuit-to-chip boundary: direct-M31 proof slice

Status: **implemented and natively verified for one four-lane repeated-step chip**, 2026-10-07. This is a builder-level proof profile. S31 source lowering and the SHA proof roster have not adopted it yet.

## What the proof says

The example circuit guesses eight private M31 wires `x[0..4]` and `y[0..4]`. It publicly outputs four sums and four products, `xᵢ+yᵢ` and `xᵢyᵢ`. A separate 16-row chip proves `y = step¹⁶(x)`, where `step(v)=v²+13`. Neither `x` nor `y` is added to the public claim. The circuit, step chip, and bridge are all components of **one** Stwo proof: one base commitment, one interaction commitment, one lookup challenge pair, one composition proof, and one FRI proof.

The proof fixes eight circuit Gate addresses in its compiled profile: four for `x` and four for `y`. The preprocessed circuit adds one producer multiplicity at each address. Its ordinary Gate AIR therefore contributes an extra negative term for the *actual* value in each addressed circuit wire. The 16-row bridge AIR commits eight private M31 columns. At every row it contributes 1/16 of each positive Gate term and 1/16 of a negative chip-start plus positive chip-end term. The step chip contributes its ordinary indexed transition terms. The verifier checks the **sum of all three component claims plus the circuit's public output terms equals zero** before verifying the three AIR components together.

Written as rational functions at the transcript's random `z, α`, with `G(a,v)` the circuit Gate tuple and `C(i,s)` the chip tuple, the extra terms are:

```text
circuit:  - Σ₈ 1 / combine(G(addressⱼ, circuit_valueⱼ))
bridge:  + Σ_rows (1/16) [ Σ₈ 1 / combine(G(addressⱼ, bridge_valueⱼ,row))
                           - 1 / combine(C(0, bridge_input_row))
                           + 1 / combine(C(16, bridge_output_row)) ]
chip:    + 1 / combine(C(0, chip_input))
         - 1 / combine(C(16, chip_output))
```

The chip's interior indexed terms telescope through its own LogUp AIR. The Gate addresses are distinct and fixed, and `G` and `C` have different relation IDs. If the rational identity holds for random challenges after the base commitment, the bridge's values must match the circuit wires and chip endpoints, except for the lookup argument's collision probability. Repeating 1/16-weighted rows does **not** make a single host equality check: each row's values are committed and constrained by the bridge's LogUp AIR. The endpoint values never pass through a verifier-supplied public word.

## Concrete AIR and proof shape

| Component | Base columns | Interaction columns | Rows in the test | Constraints |
| --- | ---: | ---: | ---: | --- |
| Direct circuit QM31 operations | 12 | 8 | 512 | Existing pinned arithmetic AIR |
| Indexed repeated-step chip | 9 | 8 | 16 | Four transition and two LogUp equations |
| Private bridge | 8 | 20 | 16 | Five paired LogUp equations |

The bridge pairs its ten rational terms into five secure columns. Each pair has a denominator that is the product of two affine tuple compressions. Multiplying that denominator by a running-sum column yields a **cubic** constraint, so the bridge advertises degree bound `log₂(16)+2` and evaluates its quotient on a 64-row domain. Both prover and verifier reconstruct this component; the proof does not supply arbitrary AIR code. The preprocessed root commits the increased Gate multiplicities, and the `S31NAT5P` profile binds the source digest, fixed addresses, chip round count and constant, circuit geometry, and Merkle root before lookup challenges.

The first local ReleaseSafe proof test produced **66,199 bytes**, with about **3.2 seconds proving** and **17–18 ms native verification**. These are one-run diagnostics dominated in part by proof of work; they are not a speed comparison. The bridge adds **zero public ABI words**. The fixture's eight public words are its sums and products.

## Negative evidence and remaining limits

[`private_boundary_proof_test.zig`](../../src/frontends/s31/private_boundary_proof_test.zig) generates the joint proof and verifies it natively. It rejects changed public words, changed bridge addresses, replay under the older direct profile, an altered bridge claimed sum, altered proof bytes, duplicate boundary addresses, and a chip endpoint witness that disagrees with private circuit wires. The bridge's unit test also mutates a committed input cell and checks the lookup sum fails.

The compiled bridge addresses must come from a **sealed verification key** when source programs use this profile. The current test supplies a fixed builder-produced specification directly to `verifyDirectPrivate`; it is not yet an S31 `.s31` language lowering or generated key package. The SHA256d chip requires its larger call tape and its four AIR components and tables to join the same proof. The prototype does not establish a concrete end-to-end collision/soundness bound or independent audit of the native verifier. Do not describe it as a Bitcoin light-client proof profile until those pieces are done.
