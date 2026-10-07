# Private circuit-to-chip boundary: direct-M31 proof slice

Status: **implemented and natively verified for one four-lane repeated-step chip**, 2026-10-07. The bridge has both a builder-level test and a narrow S31 source-level `direct-m31-private-v5` profile. The SHA proof roster has not adopted this bridge.

## What the proof says

The builder test guesses eight private M31 wires `x[0..4]` and `y[0..4]`. It publicly outputs four sums and four products, `xᵢ+yᵢ` and `xᵢyᵢ`. The [source example](../../../src/frontends/s31/examples/boundary/private_step16.s31) starts with one private `m31[4]` input, lowers `iterate<16>(step, secret)` to the chip, and publishes only `sum_lanes` of the final state. Both use a 16-row chip to prove `y = step¹⁶(x)`, where `step(v)=v²+13`. Neither example puts all eight endpoints in the public claim. The circuit, step chip, and bridge are components of **one** Stwo proof: one base commitment, one interaction commitment, one lookup challenge pair, one composition proof, and one FRI proof.

The proof fixes eight circuit Gate addresses in its compiled profile: four for `x` and four for `y`. Source lowering records them during witness-free compilation. The preprocessed circuit adds one Gate use multiplicity at each address. Its ordinary Gate AIR therefore contributes an extra negative term for the *actual* value in each addressed circuit wire. The 16-row bridge AIR commits eight private M31 columns. At every row it contributes 1/16 of each positive Gate term and 1/16 of a negative chip-start plus positive chip-end term. The step chip contributes its ordinary indexed transition terms. The verifier checks the **sum of all three component claims plus the circuit's public output terms equals zero** before verifying the three AIR components together.

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

The first local ReleaseSafe builder proof test produced **66,199 bytes**, with about **3.2 seconds proving** and **17–18 ms native verification**. These are one-run diagnostics dominated in part by proof of work; they are not a speed comparison. The bridge adds **zero public ABI words**. The builder fixture's eight public words are its sums and products; the source fixture has one aggregate public output. The sealed text package produced a **69,978-byte** proof in an acceptance run. Different build modes and fixtures make these sizes unsuitable as a performance comparison.

## Negative evidence and remaining limits

[`private_boundary_proof_test.zig`](../../../src/frontends/s31/tests/proofs/private_boundary_proof_test.zig) generates builder and source-compiled joint proofs and verifies them natively. It rejects changed public words, changed bridge addresses, changed source digest, replay under the older direct profile, an altered bridge claimed sum, altered proof bytes, duplicate boundary addresses, and a chip endpoint witness that disagrees with private circuit wires. The bridge's unit test also mutates a committed input cell and checks the lookup sum fails. The [sealed package acceptance test](../../../src/frontends/s31/tests/acceptance/acceptance_private_boundary.py) builds from readable `.s31` text, checks byte-identical lowering to the pinned relation, and rejects changed private input with a stale public claim, changed public aggregate, an injected private statement field, altered boundary key, altered source file, and altered proof bytes.

For the source profile, the key carries all eight compiler-derived addresses. Before native verification, the installed verifier re-lowers its embedded source, compares the addresses, rebuilds the private-boundary preprocessed circuit, and compares its root and circuit identity hash with the sealed key. The source shape is limited to one private `m31[4]` input, a first-node square-then-add repeat of 16–32768 power-of-two rounds, and direct-M31 lowering; the input and repeated state cannot be declared public outputs. A consistent different private witness and matching public claim can form a different valid proof. “Private” here means absent from the required public ABI, not a guarantee that STARK openings reveal no witness data. The SHA256d chip requires its larger call tape and its four AIR components and tables to join the same proof. The prototype does not establish a concrete end-to-end collision/soundness bound or independent audit of the native verifier. Do not describe it as a Bitcoin light-client proof profile until those pieces are done.
