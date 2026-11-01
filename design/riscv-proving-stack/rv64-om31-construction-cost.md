# Additive degree-eight field: construction and cost before protocol migration

This is an arithmetic/cost prototype, not a128-bit proof profile. No production protocol, field choice, transcript, verifier admission or benchmark control is switched. The M31 trace/domain remains unchanged.

## Construction and irreducibility

Let p=2^31−1, CM31=M31[i]/(i²+1), QM31=CM31[u]/(u²−(2+i)). Define OM31=QM31[v]/(v²−u). Scalar elements are a+bv with two QM31 coefficients, eight canonical M31 coordinates and32 serialized bytes. The order is p^8, slightly below2^248. It is not an integer field modulo2^248.

The new quadratic is irreducible:

1. Norm_QM31/CM31(u)=−(2+i).
2. Norm_CM31/M31(−2−i)=4+1=5, hence Norm_QM31/M31(u)=5. The sign is positive.
3. Since p≡2 mod5 and5≡1 mod4, quadratic reciprocity gives(5/p)=(p/5)=(2/5)=−1.
4. Therefore u^((p^4−1)/2)=Norm(u)^((p−1)/2)=−1. A square in QM31 would instead have that power equal1, so u is not a square. A degree-two polynomial without a root is irreducible.

Tests execute both the base-field Legendre calculation and the full124-bit-exponent QM31 Euler witness. Eliminating i and u also gives v^8−4v^4+5=0; an independent schoolbook polynomial oracle in that basis checks multiplication, squaring and inverse-by-exponentiation without invoking QM31/OM31 products. The tests cover high limbs, all coordinate serialization failures, subfields, zero denominators, tails/stripes, alias rejection and output-atomic batch failures.

[The existing Circle STARK construction](https://eprint.iacr.org/2024/278) supplies the M31 circle-domain context; no new FFT subgroup is required for this additive extension experiment. [NIST DLMF27.9](https://dlmf.nist.gov/27.9) states the Legendre-symbol interpretation and quadratic reciprocity used in step3. The norm/Euler calculation above is specific to this tower and is directly tested.

## One small arithmetic authority

`core/fields/om31.zig:Quadratic` owns the quadratic arithmetic expressions, instantiated by the concrete scalar field, packed arithmetic and actual circuit wires. Native codec, exponentiation and inversion remain concrete scalar APIs. There is no genericization of existing frontends.

Native multiply uses three inner QM31 products with Karatsuba. Multiplication by the fixed nonresidue u is a coordinate permutation plus base-field additions, rather than another general secure product. The packed API uses the existing target-native PackedQM31. On this M5 target the native width is **four**, not sixteen. `PackedOM31x16` explicitly groups four native packs into sixteen contiguous column-major rows; it does not imply a hardware16-lane instruction. Tests cover all sixteen rows independently.

The bounded non-destructive batch candidate computes OM31 norms into caller-provided QM31 scratch, reuses the existing optimized QM31 norm inverter, then applies the OM31 conjugate/cofactor. Input, output, scales and scratch are disjoint. Scratch is exactly2n QM31 values; no hidden allocation or global cache exists. Its norm/cofactor phases are currently scalar. Their cost is implementation overhead to optimize, not an inherent7× wider-field inversion penalty.

## Measured primitive and circuit cost

Three single-thread runs under the shared heavy lock,65,536 values, one warmup plus12 measured iterations per run. Entries are medians of the three per-run means. Fixed control-then-candidate ordering and the short run length make these exploratory microbenchmarks, not a controlled full-prover speedup qualification.

| Native primitive | QM31 control | OM31 candidate | Ratio |
|---|---:|---:|---:|
| Scalar multiply/add recurrence |1.135ms|2.273ms|2.00×|
| Packed secure coefficient×M31 residual accumulation |34.7µs|69.0µs|1.99×|
| Scaled batch inversion |289µs optimized owned|2.090ms bounded norm scratch|7.22× current implementation|

The inversion APIs have different ownership/traffic: the optimized QM31 owned route has36 active bytes per element(input16+output16+scale4), while this OM31 candidate has100(input32+output32+twoQM31 scratch32+scale4). These are active plane sizes, **not a count of all bytes read/written**. Control-buffer reset is outside the timed inversion call. A destructive/cofactor-packed OM31 design can reduce both scratch and repeated scalar work; this first slice intentionally records the unoptimized result.

The circuit oracle guesses all arithmetic inputs, evaluates the shared quadratic expressions through the existing QM31 circuit lane, and checks the resulting graph. Operation-only counts exclude final input-guess rows, oracle equalities and constant-finalization overhead; complete counters are retained separately.

| Operation | QM31 arithmetic rows | OM31 arithmetic rows | Extra equality rows during operation |
|---|---:|---:|---:|
| General multiplication |1|9|0|
| Secure×base |1|2|0|
| Inversion via inner norm |1|8|1 in either case|

These are existing QM31-op rows, not M31 machine instructions or complete recursive proving time. No Blake gates appear in this arithmetic fragment. Full-graph counters include input/output binding diagnostics and are stored in the receipts. Using a wider inner arithmetic representation does not automatically strengthen an outer proof that still uses QM31 challenges.

An early benchmark attempt hardcoded sixteen lanes for the target-native vector and failed. ReleaseSafe localized the out-of-bounds access; the corrected benchmark uses PACK_WIDTH and the explicit16-row grouped test prevents conflating the two representations. That failed run contributes no measurement.

## What a protocol migration must actually price

| Layer | Work/traffic affected by adopting OM31 everywhere |
|---|---|
| M31 witness and independently sized MAIN |Base trace values, ROM data and M31 FFT domains stay unchanged. Immutable MAIN/setup can still be shared. A larger challenge field does not change characteristic bounds.|
| Local and global LogUp |Every secure inverse/prefix coordinate plane doubles4→8 M31 columns, including REG, ROM, OWNER, FUNCTION, range/byte, RAM14, Keccak IO and secp Wire/truth claims. Pole/compression bounds and all provider closure must be re-instantiated.|
| Composition |Base-field SIMD residual evaluation remains base-field work. Secure random-coefficient accumulation has twice as many coordinates; arbitrary secure products cost a new quadratic layer. Degree/domain geometry does not become larger solely because the extension does.|
| OODS and DEEP |All secure points, masks, sampled values, batching randomness and quotient coefficients need the wider representation, serialization and verifier authority. Existing hardcoded four-coordinate helpers cannot be silently reused.|
| FRI and commitments |Secure FRI values, coefficient buffers and composition coordinate columns double. MAIN commitments need not double. FRI folding/query soundness and concrete ROM losses still require a separately reviewed profile; field enlargement alone does not increase query security.|
| Fiat–Shamir |A raw256-bit hash can supply eight M31 coordinates with canonical rejection, but every sampler, retry rule, domain tag and transcript dependency must match the receiver/circuit. The current raw native circuit sampler's rare retry mismatch remains a required open gate; a nonretry rejection guard is only intermediate, not full native parity.|
| Recursion |Every wider arithmetic check must be represented efficiently, and every outer proof's algebraic/hash error must meet the same whole-protocol target. The measured9/2/8-row costs make this a material architecture decision, not a free field typedef.|

For scale only: if a control had9.3G interaction cells among21.5G total cells, widening those planes alone would add9.3G cells before considering composition/FRI, wider scratch, query parameters or optimizations. That is a conditional traffic illustration, not a measurement of current LS7 geometry. Production cost must be generated from the current physical roster.

## Wider field versus repetition

Two independent whole proofs with independently adaptive Fiat–Shamir roots do not automatically multiply computational work factors. An attacker may grind a bad phase separately in each proof; costs can add instead of multiply. Shared MAIN and lockstep roots may restrict that strategy, but still need an applicable theorem covering earlier lucky replicas, later bad phases and adaptive witnesses. GKR-only repetition leaves other weak lookup, OODS, DEEP and recursive errors untouched.

A wider field avoids relying on that repetition argument for algebraic field-size terms **if integrated into every weak argument**. It still needs a complete FRI/query/ROM/hash analysis and outer recursion construction. [ethSTARK's protocol documentation](https://eprint.iacr.org/2021/582) treats the concrete construction as part of its security statement; these arithmetic measurements are not such a certificate. Neither q102/P26 alone nor the existence of this field authorizes a128-bit claim.

Before choosing a production route, compare an actually justified whole-protocol128 construction on both sides: all lookup/composition/opening/FRI error terms, adversarial work model, setup reuse, memory admission and full recursion cost. Keep the nominal96 benchmark control as the empirical baseline, clearly labeled.

## Reproduce

```
zig build test-stwo-core-om31 -Doptimize=ReleaseSafe
zig build test-stwo-core-om31 -Doptimize=ReleaseFast
zig build rv64-om31-cost -Doptimize=ReleaseFast
zig-out/bin/rv64-om31-cost 65536 12
```

Receipts: `vectors/reports/rv64-word16-execution-20261101/om31-cost-v1/`. This slice introduces no production field/transcript selection, new admission authority, whole-protocol128 certificate or GPU qualification.
