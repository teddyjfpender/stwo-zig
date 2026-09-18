# Parallel Bend CSP optimization — pass5

Continues [PR #199](https://github.com/teddyjfpender/stwo-zig/pull/199), stacked on
[PR #198](https://github.com/teddyjfpender/stwo-zig/pull/198). This pass follows the
repository's `match-algorithmic-problems` skill. The canonical mapping, alternatives,
falsifiers, sources and outcomes are retained in
`autoresearch/notes/2026-09-18-bend-parallel-csp/note.md`.

## Final repeated full-proof results

All 24 proofs verified; all 12 CPU/Bend pairs had byte-identical proof bytes.
Three alternating pairs per workload, fresh processes and cold result caches.
Both host lanes use eight Zig workers; Bend uses four processes × two native
threads. Every Bend proof observed four concurrent native requests. This table
uses the explicitly qualified no-shadow mode. Time includes guest execution,
witness and proving; verification, serialization and complete process wall time
are retained separately in `csp-final.json`.

| Workload | CPU median s | Bend median s | Bend / CPU | Previous Bend / new Bend |
|---|---:|---:|---:|---:|
| sha256 | 2.198 | 6.669 | 3.03x | 2.43x |
| keccak | 1.643 | 6.097 | 3.71x | 2.58x |
| poseidon2_m31 | 1.685 | 6.408 | 3.80x | 2.38x |
| ecdsa_secp256k1 | 16.919 | 56.684 | 3.35x | 2.56x |

**Bend improved, but CPU superiority and the requested 20x goal are not achieved.**
The comparison with pass4 is an observed checkpoint change, not an isolated
attribution: it includes scheduling, representation, transport, explicit host
worker counts and removal of duplicate shadow computation after qualification.
The checked-mode exploratory ECDSA result (67.590 s) is retained separately.
All timings are CPU-only on a shared host; these do not measure Bend GPU potential.
The final suite had no concurrent builds or kernel performance trials.

ECDSA executed 5,425,005 VM cycles. Its first final sample sent 7.212 GB and received 6.468 GB, reused 14,613 plans and 1,109 exact Bend results. Peak process RSS was 9.279 GB (a per-process high-water mark, not aggregate concurrent memory). The bridge time is accumulated across workers and must not be added to wall time.

## Parallelism is explicit and exercised

The previous CSP runner fixed Bend at one native thread, used one native session,
and serialized all native calls. The new benchmark configures four persistent
processes with two Bend threads each. Independent columns at log10 or larger are
partitioned across those sessions, with a join before the prover continues.
The native kernel retains its balanced parallel calls above flat leaf blocks.
Both CPU and Bend host services receive `STWO_ZIG_WORKERS=8`, and each receipt
checks the actual resolved Zig pool count. Peak concurrent native requests is four
in full proofs. The host has an eight-CPU quota and no GPU.

Eight native workers is a compute configuration, not a claim of eight total OS
threads: host orchestration, verification and parity workers also exist. Native
worker counts, child CPU time and wall time are retained. Small or aliased column
batches use the serial route. Worker-local allocation avoids sharing a caller's
potentially unsafe allocator. Every started job is joined even on spawn failure.

## Implemented transfers

1. **Independent column map:** replace the single locked runtime with up to eight
   separately owned sessions. This preserves column order and exact results.
2. **Compact Bend leaf plans:** use a flat, heap-indexed twiddle array in each
   256-value leaf, with iterative forward/inverse stages. Retain balanced outer
   parallel recursion. Small flat-leaf 2x LDE also skips the zero-half butterfly layer, matching
   the execution receipt. The native adapter only rearranges canonical twiddle words;
   all butterflies and M31 arithmetic remain in Bend.
3. **Buffered word fast path:** one input-block bounds check per complete word;
   retain the byte slow path for partial reads and block boundaries.
4. **Invariant plan reuse:** BND3 frames omit a session's last twiddle plan only
   after complete byte equality in Zig. No hash-only authorization. Native code
   retains canonical plan words and reconstructs affine Bend storage per request.
   This reduces wire traffic, not the mathematical computation.
5. **Qualified timing mode:** per-operation Zig recomputation remains enabled by
   default. The final timing executable explicitly disables it after 4096 FFT/IFFT
   and 2048 FRI fixtures pass against the Zig oracle. The harness requires the
   exact-binary-bound >=4096-fixture receipt. Full CPU proof verification, canonical
   guest output, cycles, transcript agreement and byte-identical CPU/Bend proof
   bytes remain mandatory. Every receipt declares `bend_shadow_check`.

The result cache remains cold per proof, bounded to 64 MiB in total across
sessions. Template storage is additional, one plan per session on each side of
the pipe (maximum approximately 64 MiB per side at log24). Shutdown frees both.
Native process requests remain bounded to 65,536 per session.

## Exploratory results and rejected work

These are retained experiments, not isolated causal speedup attributions. Some
exploratory runs overlapped compilation and kernel experiments on the shared host.

| Configuration | SHA seconds | ECDSA seconds | Shadow checks |
|---|---:|---:|---|
| Previous pass4 median | 16.194 | 145.061 | enabled |
| New 4x2 bridge, previous native kernel | 11.127 | — | enabled |
| Compact plans and fast input, 4x2 | 7.274 | 67.590 | enabled |
| Compact plans and fast input, 1x8 | 14.707 | — | enabled |

Increasing native threads alone was less effective than exposing independent
columns. The compact kernel's exploratory log22 FFT scaled from 378.675 ms at one
thread to 196.547 ms at eight. It still lost to the optimized Zig oracle. These
kernel measurements exclude native input/output conversion; full-proof timings do
not. No GPU timing or CPU superiority is claimed.

A flat 4096-value leaf candidate passed 4096 seeded fixtures and log16–24 parity,
but regressed in paired trials; it was rejected. A three-product U32 M31 candidate
used a bounded wrapping-word Karatsuba identity. It passed concrete laws and paired
kernel parity, but lacked a consistent speed win (single-thread batch multiply
regressed); it was rejected. Exact candidates, build hashes and raw trials are
retained. Generated C arithmetic was never edited.

## Verification

- ReleaseFast and ReleaseSafe backend/native integration suites pass.
- 4096 selected-kernel FFT/IFFT fixtures, plus log16/20/22/24 at eight threads.
- 2048 selected-kernel FRI fixtures, plus larger folds.
- Parallel columns match the independent Zig transform even with shadow checking
  disabled; native overlap and template reuse are observed.
- Five framing tests pass: reuse with different values, missing template, wrong
  template size, invalid legacy reuse and truncated input. Invalid frames fail.
- Seven concrete Bend boundary proofs pass; these are not universal field proofs.

`native-build.json`, `build.json`, `qualified-fft.json`, `qualified-fri.json` and
`transport-tests.json` retain hashes and receipts. Rejected candidates and all
exploratory samples remain separate from the final repeated CSP suite.
`pre-leaf-lde-csp.json` retains a completed 24-proof run before the final small-leaf
LDE correction; `pre-leaf-lde.bend` retains that exact transform source. No samples
are discarded.

## Reproduction

```sh
python3 scripts/build_bend_experiment.py --bend-root /path/to/pinned/bend \
  --output .zig-cache/bend-pass5/shared-plan-native
zig build --build-file src/integrations/riscv_bend/build.zig \
  -Doptimize=ReleaseFast -Dbend-workers=4 -Dbend-threads=2 \
  -Dshadow-check=false \
  -Dbend-executable="$PWD/.zig-cache/bend-pass5/shared-plan-native" \
  --prefix "$PWD/.zig-cache/bend-pass5/final" -j2
python3 autoresearch/benchmarks/bend_circle_fft.py \
  --bend .zig-cache/bend-pass5/shared-plan-native --oracle /path/to/bend-oracle \
  --fixtures 2048 --logs 16,20,22,24 --columns 1 --threads 8 --repeats 1 \
  --output /tmp/bend-qualified-fft.json
python3 autoresearch/benchmarks/bend_csp.py \
  --cli .zig-cache/bend-pass5/final/bin/bend-csp-bench \
  --bend .zig-cache/bend-pass5/shared-plan-native --workers 8 --samples 3 \
  --parity-report /tmp/bend-qualified-fft.json --timeout 900 \
  --output /tmp/bend-parallel-csp.json
```

Omit `-Dshadow-check=false` for the default checked mode. These are experimental
CPU measurements; Merkle, composition, typed interactions, inversion and transcript
services remain on the host. Production CSP registry admission is unchanged.
