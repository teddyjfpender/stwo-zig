# Bend optimization pass and ECDSA CSP qualification

Continues [PR #199](https://github.com/teddyjfpender/stwo-zig/pull/199), stacked on
[PR #198](https://github.com/teddyjfpender/stwo-zig/pull/198).

The requested 20x improvement and CPU superiority have **not** been achieved.
These measurements include real guest execution, witness construction and full
secure proof generation. Verification and serialization are reported separately.
The CPU backend, guest inputs, proof parameters and verifier remain unchanged.

## Repeated complete-proof results

Three alternating CPU/Bend pairs per canonical workload are retained in
`csp-final.json`. Times below include execution, witness and proving. All proof
pairs must pass independent CPU verification and exact proof-byte equality.

| Workload | CPU median seconds | Bend median seconds | Bend / CPU |
|---|---:|---:|---:|
| sha256 | 2.284 | 16.194 | 7.09x |
| keccak | 1.721 | 15.718 | 9.13x |
| poseidon2_m31 | 1.661 | 15.248 | 9.18x |
| ecdsa_secp256k1 | 17.225 | 145.061 | 8.42x |

All 24 proofs verified; all 12 CPU/Bend pairs were byte-identical. ECDSA
Bend samples were 145.676, 143.025 and 145.061 seconds. CPU samples were
19.529, 17.225 and 16.667 seconds. The median ratio is 8.42x slower.

## Changes

- Serialize each Circle twiddle plan once per batch and encode canonical M31
  arrays in bulk on little-endian hosts.
- Add an opt-in bounded cache of exact native requests and Bend-produced results.
  The CSP runner starts cold with a 64 MiB cache for each proof. Hashes only find
  candidates; complete request bytes must match before reuse. Shutdown clears
  the cache. Reused results still pass independent Zig parity checks.
- Record actual native calls, cache hits, request/response bytes, bridge duration,
  Circle preparation and Circle oracle time. Timing categories can overlap across
  host threads; they must not be summed as a wall-time decomposition.
- Include canonical ECDSA secp256k1 in the default CSP suite. Save each verified
  lane immediately so a subsequent failure cannot discard its counterpart.
  Bind integration Zig source hashes in addition to backend and Bend sources.

## Exploratory measurements

The first SHA sample measured CPU 2.083 s and Bend 16.206 s. The cache avoided
456 native requests, but still sent 1.234 GB and received 0.613 GB. Its accumulated
bridge duration was 15.719 s; Circle oracle duration was 1.064 s.

The first ECDSA pair executed 5,425,005 VM cycles: CPU 22.095 s, Bend 145.868 s,
6.60x slower. Both proofs verified and their serialized bytes matched. Bend made
15,011 native requests and reused 1,977 exact prior results. Traffic was 12.335 GB
sent and 6.164 GB received. Peak process RSS was 9.25 GB. The accumulated bridge
duration was 110.071 s and Circle oracle duration 10.422 s. These observations
identify remaining work; they do not establish exclusive attribution of cost.

`csp-exploratory.json` retains these raw observations. Some exploratory ECDSA
execution overlapped local compilation and kernel trials, so the final repeated
suite is the preferred comparison. No sample is silently removed. `ecdsa-cpu-initial.json` also retains the first
standalone CPU run (26.464 s), before the paired suites.

## Rejected FFT tuning

A pure Bend candidate increased local subtransform leaves from 256 to 4096
values. Its exact source and build receipt are retained beside the raw matrix
and alternating baseline/candidate comparisons. It passed 64 seeded small
fixtures and FFT/IFFT parity at log16, log20 and log22, three samples per cell.

The paired log20 FFT/IFFT kernel changes were only about 1.07–1.10x. Unchanged
multiply and prefix also moved, including a 1.80x prefix result, demonstrating
noise in that exploratory run. The candidate has not been adopted: these data
do not establish an end-to-end improvement. Increasing problem size alone did
not demonstrate superiority over Zig. Generated C arithmetic was not edited.

## Validation and limitations

ReleaseFast and ReleaseSafe backend/native integration suites pass, including
cache-hit parity, a changed request forcing native execution, and cache clearing
on shutdown. All numerical parity checks remain enabled. The experimental proof
backend continues using host Merkle commitments, composition, typed interactions,
inversion and transcript services. There is no all-Bend or GPU claim. No GPU is
available on this host. The native Bend algorithm is the qualified pass3 binary.

Reproduction (after building the pinned native runner and integration package):

```sh
python3 autoresearch/benchmarks/bend_csp.py \
  --cli .zig-cache/bend-pass4/profile/bin/bend-csp-bench \
  --bend .zig-cache/bend-pass3/native \
  --samples 3 --timeout 900 \
  --output /tmp/bend-csp-pass4.json
```

For ECDSA alone add `--targets ecdsa_secp256k1`. Each proof runs in a new process,
with alternating CPU/Bend order, authenticated canonical inputs, 26 proof-of-work
bits, 70 queries, 2x blowup and the existing CPU verifier. The suite requires
matching public outputs, cycles, proof bytes and actual Bend transform/FRI calls.
