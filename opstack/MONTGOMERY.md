# Optional Arkworks Montgomery service client

The anchored derivation guest spends substantial work in blob interpolation
and BLS12-381 KZG verification. `montgomery-services` replaces four- and six-limb
Arkworks Montgomery products with the **existing** admitted `arith384_mont`
service (`0x00030121`). Native builds keep the software implementation. The
feature is off by default and does not enable a new prover protocol.

For a six-limb field the service directly computes `ab 2^-384 mod m`. For a
four-limb field the packet encodes `a << 128`, so the same relation computes
`ab 2^-256 mod m`. The first input may exceed `m`; the admitted relation accepts
arbitrary 384-bit operands and constrains a canonical output. No field element
is decoded to canonical storage between products. Canonical-storage backends
retain their own methods. Zero/one shortcuts and canonical `from_bigint`
rejection are preserved. Ark's derived configuration overrides multiplication,
so interception belongs at the `FpConfig` implementation, not the derive's
configuration defaults.

The inline packet is exactly 160 bytes, aligned to 32 bytes, with six words
each for `a`, `b`, `m` and two padding words. Every word is initialized. Literal
limb construction and XOR/OR equality reductions avoid bytewise runtime
copies and comparisons. The first generic-array implementation was rejected:
its `memcmp`, `memcpy` and `memset` glue consumed more than half of an actual
probe's retired instructions and erased much of the arithmetic saving.

## Execution qualification

[Receipt](../vectors/reports/rv64-opstack-cpu-20261108/arkworks-montgomery-service.json).
Both columns use identical inputs and independently checked outputs.

| Actual RV64 task | Software instructions | Service instructions | Instruction ratio |
| --- | ---: | ---: | ---: |
| Dense blob, reference fraction method | 9,164,654 | 3,250,010 | 2.82x |
| Dense hashed blob, production adaptive method | 6,876,987 | 2,906,789 | 2.37x |
| Complete single-blob KZG verification | 51,367,828 | 28,486,651 | 1.80x |
| Complete two-blob KZG batch verification | 73,334,596 | 40,544,466 | 1.81x |

Twelve field probes and both KZG probes agree with separate native software
and Unicorn execution: output, exact instruction count, all registers, final
PC and service counts. Field values additionally agree with independent Python
polynomial arithmetic. KZG vectors are the pinned c-kzg vectors; Python checks
framing, not KZG cryptography. Invalid proof/blob, noncanonical scalar,
duplicate blob, truncation and count violations trap without successful output.

Physical curve-service tests use a shifted BLS scalar `(p-1)<<128` input above
`m`, then reuse the in-place result across two CPU shards. CPU, bridge, truth,
global RAM and independently built durable-wire receiver keys all verify.
Forged input/output/pointer mutations reject. Algebraic rows cover both scalar
moduli at zero, one and modulus-minus-one. The pure packet test uses independent
BigUint arithmetic for 128 pairs in each of four- and six-limb representations.
The full host suite (40 tests), Python suite (40 tests), RV64 execution suite,
curve AIR suite and curve services suite pass. The complete
`transition-sha-montgomery` guest also builds.

These are **execution instruction reductions**, not measured complete prover
speedups. Each service adds a truth/bridge proof obligation; that cost must be
included before selecting a production guest. The retained full anchored
transition input is still missing, so no full-transition latency is claimed.
Security remains a 128-bit target under documented assumptions, unqualified.

## Reproduction

```sh
python opstack/build.py --variant blob-eval-probe --artifacts /tmp/blob-control
python opstack/build.py --variant blob-eval-services --artifacts /tmp/blob-services
python opstack/tools/blob_evaluation_bench.py --build /tmp/blob-control --artifacts /tmp/blob-control-results
python opstack/tools/blob_evaluation_bench.py --build /tmp/blob-services --artifacts /tmp/blob-service-results --oracle
python opstack/tools/blob_evaluation_bench.py --build /tmp/blob-services --artifacts /tmp/blob-kzg-results --kzg --oracle --timeout 900
zig build test-riscv64-curves-truth test-riscv64-word16-curves-services -Doptimize=ReleaseFast
```

Use each ELF's own symbols and hash; `heap_start` can move between builds.
`BP` diagnostic outputs cannot enter the OP/OD proof harness. The oracle only
accepts them when the caller explicitly selects `output_kind="blob-probe"`.
`transition-montgomery` and `transition-sha-montgomery` are the corresponding
anchored derivation build choices; the latter also uses SHA-256 compression.
