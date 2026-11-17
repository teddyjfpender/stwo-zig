# Canonical BLS12-381 Fr255 guest adapter

The opt-in `canonical-fr` feature uses the existing `arith256_mod` relation for
BLS12-381 scalar products. It avoids canonical-to-Montgomery service conversions
and moves four-limb products from the generic 384-bit Montgomery provider to the
256-bit provider. Selected guest binaries, default features and protocol profiles
are retained. The new build variants are `blob-eval-canonical-fr` and
`transition-sha-canonical-fr`; neither is selected automatically.

## Representation and authority

The vendored ark-bls12-381 0.6.0 preserves the published source and licenses.
Its scalar adapter sets R=R2=1 and supplies the canonical generator, two-adic root
and large-subgroup root. Strict bigint decoding rejects values at or above p;
serialization returns the canonical limbs. The inherited binary inverse starts
at coefficient 1; generic additions, subtraction, negation and Tonelli–Shanks use
the canonical configuration. Independent reference tests cover these properties,
high-end values, serialization, and scalar-group multiplication.

Blob-root selection follows the actual FrConfig representation, including Cargo
feature unification. Both 4096-root tables are generated independently with
Python; the original Montgomery table is unchanged. Canonical roots add no
runtime field conversion. All constants are bound through the new program image.

RV64 products use tag `0x30021` and the existing 160-byte packet
`a[4], b[4], c=0[4], modulus[4], output[4]`. Output occupies words 16–19.
Native builds use a separate software Montgomery reference and issue no ECALL.
The BLS base field Fq381 retains its existing representation/service. No new AIR,
lookup relation, ABI tag, protocol enum or receiver acceptance rule is added.

The relation already proves arbitrary 256-bit `(a*b+c) mod m` and a canonical
output. This adapter always supplies the fixed nonzero Fr modulus and canonical
operands. Existing RAM/Wire/OWNER joins and request-derived bounds still apply;
there is no host-supplied unconstrained field result.

## Qualification and cost

The receipt `canonical-fr255-v1.json` pins matched source-guarded ELFs and symbols.
All 14 native library tests pass, including three independent property suites
and existing blob/KZG adversaries. The real retained anchored transition has
identical native statement and OD bytes under the canonical backend.

Three bounded RV64 probes agree with independent Python field arithmetic and
Unicorn on output, PC, registers, instruction and service counts:

| Probe | Montgomery instructions | Canonical instructions | Service calls |
| --- | ---: | ---: | --- |
| Dense hash | 2,650,944 | 2,375,230 | 12,300 Mont384 → 8,203 arith256 |
| Sparse | 1,424,602 | 1,339,041 | 19 Mont384 → 16 arith256 |
| On domain | 1,399,012 | 1,165,239 | 4,102 Mont384 → 5 arith256 |

Dense retirements fall 10.4%. This is an isolated interpolation result, not a
whole-block proving benchmark. No full transition RV64 replay or STARK proof was
performed for this candidate.

The existing OM31 provider widths, read from their source layouts, are
401 MAIN + 976 INTER for arith256 versus 520 + 1472 for Mont384. Applying the
separately qualified native branch model to the new fixture removes 61,526
conversion packets and routes 122,995 products through arith256, leaving 131,399
Mont384 calls. Active field-provider cells model 629,312,640 → 431,110,923; one
idealized instance per family models 1,044,381,696 → 702,676,992 padded cells.
These counts exclude CPU, bridge, fixed columns, lifted hashing and the driver's
actual shard geometry. Both packet ABIs are 160 bytes; no per-call packet-width
saving is claimed.

The Montgomery native census refuses a canonical configuration because its
software fallback would count reference conversions rather than guest calls.
The remaining large derivation investigation is Brotli allocation/copy work;
existing raw-input and blob-fold optimizations should not be counted twice.
