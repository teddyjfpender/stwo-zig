# Typed ECDSA precompile at canonical CSP parameters

2026-09-21, Apple M5 Max, AC power, Zig 0.15.2, ReleaseFast.

The existing typed secp256k1 provider already meets the sub-second target on the
canonical CSP ECDSA input at **70 FRI queries and 26 PoW bits**. No production
prover optimization or security reduction was needed. This is a measured
provider baseline, not a speedup claim or an end-to-end CSP guest result.

| Backend | Median proving | Mean proving | Measured proving range | Median fresh verification |
|---|---:|---:|---:|---:|
| CPU | 228.375 ms | 228.791 ms | 227.187–230.994 ms | 9.882 ms |
| Metal | 164.542 ms | 163.402 ms | 152.463–170.381 ms | 9.984 ms |

Each backend performed one warmup and ten measured proofs; every proof passed
an independently reconstructed verifier transcript. All ten measured samples
on each backend were below one second. Proving includes ECDSA witness generation,
preprocessed/main/interaction commitments, interaction generation, and the full
cryptographic prover including PoW. Verification is reported separately. Build,
Metal runtime/AOT initialization, and final resource destruction are outside
these stage timers. This is a warmed provider measurement, not process-start latency.

## Exact workload and scope

The 161-byte input is byte-identical to
`vectors/riscv_csp/inputs/ecdsa_secp256k1.bin`, SHA-256
`5136df6e9b49321531a2d337dc227939ecc68645036b597bdcc0e531333ad3ff`.
The request contains a 32-byte digest, a 65-byte SEC1 public key and 64-byte signature.
The ten existing typed components prove the ECDSA provider transaction with the
public call counterpart supplied directly. There is no RISC-V execution/caller
or guest memory composition in this harness. Invalid-signature guest behavior
is not qualified by this positive-provider benchmark.

PCS settings match the canonical CSP contract: PoW 26, queries 70, log blowup 1,
last-layer log degree bound 0, fold step 1, no lifting override. The old default
proof gate remains at its small test settings. Explicit
`STWO_SECP256K1_CSP_SAMPLES=10` selects the fixed CSP profile and repeats fresh
proofs, rather than reusing a proof or a cached nonce.

Both backends returned the same PoW nonce, **560,941**. This fixed transcript has
a favorable search length compared with the 2^26 expected trials for random
challenges. Nothing was changed to select this nonce; it was discovered by the
ordinary prover and checked by the verifier on every run. Repeating the same
fixture measures host timing variation, not the PoW distribution over different
statements. These results do not establish a sub-second guarantee for arbitrary
signatures. Proof-byte equality was not measured in this provider run.

Metal telemetry recorded 363 dispatches and 33 CPU fallbacks over the eleven
proofs (33 dispatches and 3 fallbacks per proof). This is hybrid Metal proving.
The host is not the official CSP M1/8-core/16-GB comparison host.

## Retained change and validation

The harness now exposes parameterized execution and an opt-in repeated CSP mode;
both CPU and Metal test entrypoints use that selector. No production arithmetic,
AIR, transcript, precompile ABI, or backend kernel changed. The default CPU and
Metal proof gates also passed after the benchmark run. Only these focused gates
were run; no full repository test suite was needed for a harness-only change.

[Commands](commands.sh), [raw CPU output](cpu.log), [raw Metal output](metal.log),
[all samples and stage medians](results.json), [metadata](metadata.json),
[benchmark patch](benchmark.patch), and [source hashes](source-sha256.json)
record the experiment. The measured working tree is dirty; the source hashes
pin 5,089 Zig/Zon/native-kernel input files. This is local research evidence,
not a clean-snapshot release qualification.

## Next product step

The ordinary CSP manifest still declares `uses_precompile=false`, so its
previous CPU 3.737 s / Metal 1.937 s ECDSA row remains unchanged. A separate
precompile-enabled guest lane must compose the caller and memory relations,
preserve verification failure semantics, and pass the canonical valid and
invalid input checks before publishing an end-to-end CSP precompile row.
The existing Ethereum signer-recovery instruction is a different, successful-only
ABI and cannot silently stand in for that ECDSA-verification contract.

For this fixed provider target, further optimization is unnecessary. If the
next target becomes latency across varying statements, measure the PoW tail
first; the fixed-fixture timings here do not answer that question.
