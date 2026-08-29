# Typed-AIR CSP throughput campaign

- Date: 2026-08-29
- Starting commit: `19c56b8ad487ead305db5047ee3882d2f42c549d`
- Host: Apple M5 Max, arm64 macOS, Zig 0.15.2
- Boundary: complete secure RISC-V CSP proof plus in-process verification
- Target: pursue a 10x improvement without changing proof bytes, security
  parameters, statement semantics, transcript order, or the 16-worker envelope

## Outcome

The campaign did not reach 10x. It produced meaningful, proof-identical
constant-factor gains and established why a 10x local implementation win is
not available at the current protocol boundary: after the accepted changes,
CPU Keccak is still dominated by the mandatory 26-bit BLAKE2s proof-of-work
search, while Metal has moved that search to the GPU and is increasingly
bounded by the remaining proof construction and verification pipeline.

The final reverse-balanced CSP measurements are:

| backend | workload | baseline request | candidate request | request change | baseline prove | candidate prove | prove change |
|---|---|---:|---:|---:|---:|---:|---:|
| CPU | Keccak/128 | 1.118812 s | 0.916212 s | **-18.11%** | 0.951586 s | 0.746550 s | **-21.55%** |
| CPU | Poseidon2/16 | 0.984674 s | 0.954437 s | **-3.07%** | 0.744422 s | 0.704149 s | **-5.41%** |
| CPU | ECDSA/32 | 4.442668 s | 4.245100 s | **-4.45%** | 3.567655 s | 3.360223 s | **-5.81%** |
| Metal | Keccak/128 | 1.231824 s | 0.782918 s | **-36.44%** | 1.083664 s | 0.637995 s | **-41.13%** |
| Metal | Poseidon2/16 | 0.883902 s | 0.776672 s | **-12.13%** | 0.679183 s | 0.573465 s | **-15.57%** |
| Metal | ECDSA/32 | 3.806537 s | 3.269912 s | **-14.10%** | 2.945220 s | 2.401952 s | **-18.45%** |

Each cell is the adjacent average of two three-sample runs in A/B/B/A order,
with one warmup per run. CPU Keccak cycles fell 25.70%; Metal Keccak host
cycles fell 82.35% because the formerly host-bound search moved to the GPU.
The complete one-sample 16-case CSP diagnostic matrix produced geometric-mean
request improvements of 4.25% on CPU and 16.82% on Metal. All 16 cases retained
exact proof, statement, and transcript identity across predecessor/candidate
and CPU/Metal lanes.

## Retained changes

### Backend-authenticated Metal proof of work

The Metal backend now owns a deterministic BLAKE2s proof-of-work kernel. It
searches bounded contiguous intervals, atomically publishes the minimum match,
and advances only after each interval completes. The generic PCS layer
revalidates the returned nonce before transcript publication. A 2^24 interval
was the best measured launch/amortization point.

The fixed 40-byte message has a 32-byte request prefix and an eight-byte nonce.
The Metal implementation precomputes the four prefix-only column G functions
from BLAKE2s round zero. Each GPU candidate executes the remaining
nonce-dependent diagonal work and rounds 1--9. This reduced direct GPU search
time by about 14.3% on Keccak, Poseidon2, and ECDSA on top of the larger
CPU-to-GPU offload gain.

The shader ABI is fail-closed, the native and AOT manifests expose the exact
new kernel, AOT/JIT export parity is retained, and CPU/non-BLAKE2s routes keep
their existing search policy.

### Prepared-prefix CPU proof of work

The CPU path now prepares seven of round zero's eight G functions once per
request. Eight SIMD nonce candidates begin from that prepared state, execute
only the nonce-dependent round-zero G plus rounds 1--9, and return digest word
zero for the admitted difficulty of at most 32 bits. Higher difficulties keep
the full-digest fallback.

The overwhelmingly common miss path masks and compares all eight first words
as vectors and reduces the match flags once. It enters an ordered scalar scan
only for a batch containing a match, preserving the exact lowest nonce.
Randomized differential tests compare every lane against complete BLAKE2s.

### Divide-free packed previous-row mapping

The CPU composition lane replaces repeated power-of-two division in the
four-row previous-circle mapping with one shared bit-reversed base and a
lane recurrence. Exhaustive log-size 2--20 tests bind the mapping. The isolated
index operation is substantially cheaper, but its complete-request effect is
only about 0.3--0.6%; it is retained as a small, low-risk supporting win.

## Correctness identities

The final A/B matrices produced these exact decoded proof identities on both
backends:

| workload | proof bytes | SHA-256 |
|---|---:|---|
| Keccak/128 | 827,978 | `b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8` |
| Poseidon2/16 | 1,089,948 | `d8d121e4acdc0159d468337268f9cea1f917bbd0252051de9628070307c70ae5` |
| ECDSA/32 | 3,304,541 | `eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d` |

The product wrapper identity changes because it records the dirty
autoresearch source/binary identity; the authenticated protocol proof does not.

## Rejected experiments

More than two dozen candidates were measured and removed or left as explicit
future milestones. Important falsifications include:

- dedicated 18-worker CPU PoW was faster but violates the fixed 16-worker
  benchmark/resource envelope;
- dynamic PoW chunk scheduling was neutral;
- splitting eight SIMD candidates into two four-lane compressors was neutral;
- cooperative four-lane GPU BLAKE2s was slower;
- a larger or smaller Metal PoW interval lost to dispatch overhead or excess
  work;
- prepacking and compacting composition programs did not survive complete CSP
  A/B measurement;
- vector previous-row gathers over-fetched and regressed ECDSA;
- larger quotient tiles, narrower QM31 inverse chains, forced Metal inlining,
  cooperative Merkle leaves, and alternate threadgroup widths were neutral or
  slower;
- lookup batching V2 reduces columns and proof size, but changing the ordinary
  CSP product's authenticated V1 statement is a separate protocol milestone;
- exact-sized verifier buffers saved less than 0.4 ms and did not reduce
  instructions;
- caching the CPU PoW published bound for 64 batches saved only about 0.2% and
  was reverted;
- replacing eight checked nonce increments with one batch-wide bound reduced
  instructions 0.69% but cycles only 0.18% and proving about 0.31%, so it was
  reverted as noise-sized;
- finalizing only Metal BLAKE2s word zero at 26-bit difficulty left direct GPU
  time flat (59.291 ms versus 59.324 ms) and was reverted;
- reusing one verifier node-domain seed failed the large-shape confirmation
  (ECDSA verification 149.694 ms versus 152.786 ms) and was reverted;
- four-parent SIMD multiproof hashing was neutral on ECDSA (149.552 ms versus
  149.584 ms) after a noisy small-shape hint and was reverted.

No rejected implementation remains in the source tree.

## Profiling conclusion

A post-candidate process sample over ten secure Keccak requests recorded 14,767
top-of-stack samples in `pcs.proof_of_work.PowWork.run`; the next active crypto
symbols were the BLAKE2s compressors. Generic composition, quotient, lookup,
FFT, and Merkle functions were an order of magnitude smaller individually.
This confirms that further material CPU gains require a new PoW implementation
strategy or a protocol/security decision, not another local typed-AIR loop
tweak. The Metal path has already taken the sound hardware-offload route.

## Evidence and interpretation

Raw local evidence is retained outside the repository under
`/private/tmp/stwo-typed-air-csp-10x-20260829/evidence`. The controlled final
comparisons are `final-cpu-compounded`, `final-metal-compounded`, and
`final-csp-16-matrix`; the complete chronological research transcript is
`/private/tmp/stwo-typed-air-csp-10x-20260829/transcripts/session-01.md`.

These are local autoresearch measurements, not a clean immutable release
receipt. The useful promotion claim is the proof-identical implementation and
its measured same-host direction. A clean commit and CI/release run should
rebuild the final products and emit the repository's normal immutable evidence
before release.

The exact retained-source ReleaseFast build completed with CPU executable
SHA-256 `6a0cbd2adcc0208c9e1ac6c0cbdf1da6f987980b32367ef284285f802951292d`
and Metal executable SHA-256
`7d3bf1c4c2e45675759270fcb4e75b3094ec2e408ffa740eaa3189b1bef9f1b3`.
Fresh Keccak verification passed for both. Final Metal profiling recorded 13
dispatches of `stwo_zig_blake2s_pow_search` and no missing PoW route.

ReleaseFast validation passed for the core crypto differential fleet, PCS
commitment/lowest-nonce fleet, Metal proof-of-work parity gate, and both final
products. `zig fmt --check`, `git diff --check`, and source conformance are
green.

## Next research frontier

1. Develop an authenticated reusable-preprocessing/session product so repeated
   CSP requests can amortize profile-invariant commitments without changing a
   single-request proof.
2. Continue generated-executor work only where profiling demonstrates a large
   active interpreter region; bytecode compaction alone is insufficient.
3. Activate lookup batching V2 through an explicit statement-version migration
   and measure its full 16-case portfolio.
4. Treat any lower PoW difficulty, cached nonce, or altered query count as a
   protocol experiment, never an implementation optimization.
5. Optimize the post-PoW Metal critical path around resident proof construction
   and verifier overhead; the search kernel is no longer the only major stage.
