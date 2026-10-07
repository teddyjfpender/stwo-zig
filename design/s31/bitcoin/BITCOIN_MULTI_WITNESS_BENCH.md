# Bitcoin proof benchmark across three headers

This benchmark runs the same `bitcoin_header_pow` S31 program with three valid
historical mainnet headers. Each proof has one private 80-byte header and one
public eight-word Poseidon2 digest root. The relation requires byte-exact
SHA256d of the header and checks that the resulting 256-bit value is at most
the mainnet compact target encoded in the header. The three backends are the
generic sparse-wide circuit, SHA shift v3, and fused SHA v4. Each native
verifier authenticates its own proof against the same source and public root.

## Reproduce

From the repository root:

```sh
(cd src/frontends/s31 && zig build bench-bitcoin-multi-witness -Doptimize=ReleaseFast)
python3 src/frontends/s31/benchmarks/benchmark_multi_witness_bitcoin.py \
  src/frontends/s31/zig-out/bin/s31-bitcoin-multi-witness-bench \
  --rounds 5 \
  --out design/s31/measurements/bitcoin/bitcoin-multi-witness-generic-v3-v4-2026-10-07.json
```

The build target only compiles the executable; the Python command performs the
timed run. It rejects Zig test-mode output because the Zig test runner disables
the prover's global work pool and uses a single PoW worker. Use an idle machine
for comparable wall times. A round runs all nine profile/header pairs, rotating
backend order. The recorded five rounds produce 15 samples per profile.

## Witnesses and checks

| Name | Fixture | Bitcoin block hash, display order |
| --- | --- | --- |
| Genesis | `examples/bitcoin/bitcoin_header_pow.valid.json` | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` |
| Height 1 | `examples/bitcoin/bitcoin_header_link.valid.json`, `private_inputs.child` | `00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048` |
| Height 2 | `examples/bitcoin/bitcoin_block2_header.valid.json`, `header_hex` | `000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd` |

The executable independently hashes each 80-byte header twice with SHA-256,
checks it against the compact target, computes the Poseidon2 leaf root, and
checks that the S31 interpreter returns that root. It compiles each assignment
through both circuit paths, checks topology and boundary addresses, then
constructs all three native proofs. Every serialized proof is verified against
its expected public root, source digest, and backend key. Repeated trials of a
given profile/header must produce identical serialized proof bytes; this also
checks that canonical PoW nonce selection is stable across worker schedules.

## What the record means

The JSON record stores all raw samples, the three witnesses, setup, per-profile
medians and quartiles, and per-witness medians. Its principal non-PoW ratio is
the median of the three per-witness ratios. Repeated rounds for one header are
timing repetitions of one deterministic transcript, **not** new PoW nonce
draws. The three distinct headers provide three distinct transcripts per
profile. The record also keeps pooled sample medians for diagnostic comparison.

`prove_ns` is wall time inside the prover call, excluding serialization and
verification. `interaction_pow_ns` and `fri_pow_ns` are separately timed PoW
searches; `nonpow_ns = prove_ns - interaction_pow_ns - fri_pow_ns`. The full
`prove_ns` is the total prover wall time, including both PoWs. `verify_ns` is
native verification of serialized bytes. Fixed commitments and keys are built
before the timer for **all** three profiles. V3/v4 also expose composition
evaluation and FRI quotient commitment substage timings. The benchmark uses
one in-process general-purpose allocator and FRI configuration
`FriConfigV2.init(26, 0, 1, 70, 1)`: 26-bit FRI PoW, log last-layer degree
bound 0 (absolute degree bound 1), blowup log 1, 70 queries, one fold per step.
Each profile uses 20-bit interaction PoW.
Matching these numeric FRI settings does not by itself establish equivalent
security margins for the different AIRs.

These results measure three headers and one machine, not sustained throughput
or recursive verification. The private header and SHA digest are absent from
the public statement; current trace openings are unmasked, so the proofs do
not claim zero-knowledge confidentiality. Proof formats and sizes differ among
the three profiles even though the source relation and public output match.

## Measured result, 7 October 2026

The [raw record](../measurements/bitcoin/bitcoin-multi-witness-generic-v3-v4-2026-10-07.json)
contains all 45 native-verified samples. Pooled timings below are medians in
milliseconds; bracketed values are first and third quartiles. Proof bytes
are medians across the three headers.

| Profile | Non-PoW prover | Total prover, including PoW | Native verifier | Proof bytes |
| --- | ---: | ---: | ---: | ---: |
| Generic sparse-wide | 154.04 [152.65, 155.85] | 214.54 [213.41, 371.27] | 4.11 | 338,282 |
| SHA shift v3 | 43.18 [42.63, 44.29] | 130.84 [58.03, 451.26] | 7.11 | 502,783 |
| Fused SHA v4 | 39.41 [39.10, 39.74] | 264.00 [178.55, 410.72] | 4.74 | 375,911 |

Per-header non-PoW medians show whether the benefit persists across the
three distinct witnesses:

| Header | Generic | V3 | V4 | Generic / V4 |
| --- | ---: | ---: | ---: | ---: |
| Genesis | 152.95 ms | 43.05 ms | 39.19 ms | 3.90× |
| Height 1 | 154.48 ms | 43.42 ms | 39.41 ms | 3.92× |
| Height 2 | 153.87 ms | 43.18 ms | 39.45 ms | 3.90× |

The median of per-header ratios is **3.56× generic/v3**, **3.90×
generic/v4**, and **1.10× v3/v4** for non-PoW proving. FRI PoW is deterministic
for each transcript but its search length differs sharply across the three
headers and proof formats; the total prover column therefore does not preserve
the non-PoW ranking. It is shown in full rather than hidden by subtraction.
