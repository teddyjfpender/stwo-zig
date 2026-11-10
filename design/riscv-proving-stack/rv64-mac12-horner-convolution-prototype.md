# MAC12 same-residual Horner factorization prototype

2026-11-10. Isolated source-only evaluator experiment. The current qualified MAC12 AIR, projections, v3 transport, transcript, constraint roster and R5/R6/R7 production paths are untouched. No native or recursive proof was produced or timed. There is no source-key, format or admission change.

The helper is `src/integrations/riscv_cpu/delegations/op_pairing_horner/fold.zig`. It returns exactly the existing 65 convolution residuals folded in their original order, rather than individually constructing each convolution and multiplying each result by the Horner challenge. The original residual source is `src/frontends/riscv/rv64/air/delegations/bn254_mac12/source.zig:80`. Tests obtain their reference slice directly from **that unchanged `Source.emit`**, not a rewritten shadow reference.

For the original residuals c[0] through c[64], the sink yields

```
C(alpha) = sum_n c[n] alpha^(64-n).
```

Let each operand's bytes be ordered little-endian in MAIN, as they are in the original source. Define

```
AH(t) = sum_i a[t,i] alpha^(31-i)       (i=0..31)
BH(t) = sum_i b[t,i] alpha^(31-i)       (i=0..31)
QH    = sum_i q[i]   alpha^(32-i)      (i=0..32)
PH    = sum_i p[i]   alpha^(31-i)      (i=0..31)
DH    = sum_i (acc[i]-out[i]) alpha^(31-i)
CH    = sum_j carry[j] alpha^(63-j)    (j=0..63)
```

Each actual signed carry is the three-byte value minus `active*OFFSET`. The result is

```
C(alpha) = alpha^2 sum_t coefficient[t] AH(t) BH(t)
         + alpha^33 DH
         - (1-2*sign) alpha QH PH
         + (1-256*alpha) CH.
```

Proof: multiplying AH and BH assigns the pair of byte indices i,j exponent 62-i-j; the leading alpha² makes this 64-(i+j), the original convolution exponent. QH×PH has exponent 63-i-j and the leading alpha makes it 64-(i+j). DH needs alpha³³ to obtain 64-i. A carry[j] appears positively in residual j+1 and negatively with coefficient 256 in residual j, giving alpha^(63-j)(1-256alpha). Summing is valid over the entire extension field. Coefficients, active masks and signs need not be base-field, canonical or Boolean for the identity to hold. No inverse is used, so alpha=0 and alpha=1 are covered directly.

This is **evaluation of the same randomized combination**, not removal of constraints or a replacement soundness argument. It does not claim that one folded value determines all 65 residuals. Appending the slice to a preexisting sink accumulator h requires `h*alpha^65 + C(alpha)`, with precisely the old order; that identity is tested, but the shared sink/engine is not changed.

## Qualification and operation census

Run from the repository root:

```
scripts/rv64_pairing_horner_test.sh --test-filter 'MAC12 Horner prototype'
```

All five ReleaseSafe tests (including the focused root import) pass:

- Twenty arbitrary rows with **all eight OM31 coordinates** independently populated in every MAIN and FIXED value; alpha zero, one, minus one and independent random extension values.
- Honest canonical edge witnesses with all +18, all −18, zero and mixed coefficients, including positive/negative quotient signs. Extension-valued corruptions of active, input edges, accumulator, output, sign, quotient edges, carry edges and fixed coefficients preserve equality to the original emitted slice.
- The prior-accumulator append identity.
- A distinct external arithmetic lane delegates numeric semantics to OM31 and counts every add/sub/mul, exposing exact generic operation counts rather than CPU timings.
- Sixteen packed secure lanes with independent arbitrary rows and independently varied challenges; each matches both original packed `Source.emit` and its separate scalar lane.

| Generic secure operations | Original 65 residuals | Original slice's Horner fold | Factored helper |
|---|---:|---:|---:|
| Multiplications | 14,806 | 65 | 1,099 |
| Additions | 14,580 | 65 | 1,074 |
| Subtractions | 354 | 0 | 68 |

Thus 14,871 → 1,099 generic multiplication calls, **13.53× fewer for this isolated slice**. Constant construction is outside this operation counter; source literal constants are supplied explicitly. The counter includes base-literal multiplies and does not model an optimizing symbolic compiler's zero/one folding, base-versus-extension specialization, temporary lifetimes, physical native-dot/OMUL rows, other constraints, masks or openings. It is neither an actual recursion-cell reduction nor a proving-time measurement.

## Next gate, not implemented

The whole-pairing recursive statement still needs symbolic transcript-derived binding data (see `rv64-whole-pairing-op-p2-r7-integration.md`). This helper can later receive those circuit lane values through ordinary field operations; it does not bake numerical transcript challenges into a key. Before any live bulk-sink use, qualify exact old operation order around the 65-element slice, alpha powers, the final combination of every other constraint, and source/witness/canonicality authority. Then measure actual source IR costs and retained valid proof/key behavior. No present result permits a whole-provider or full-block speed claim.
