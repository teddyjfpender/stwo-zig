# ZisK / Stwo component benchmark campaign

Scope: the recursion/proving path and its hash/precompile primitives, not every
utility function in the ZisK repositories. This campaign is in progress.

## Completed: portable scalar hash and witness probes

Pinned Proofman d485fac207679076958b502554fb595568c2f954, Zig 0.15.2 C++ -O3 and
Zig ReleaseFast, native ARM code generation on the same powered host. Four samples
per arm in interleaved order, with warmup/calibration. C ABI crossings occur once
per timed batch. Full output checksums prevent eliminating compression/hash calls.
Peer source is unmodified. Output parity covers 23 hash/stream/XOF cases including
chunk boundaries and noncanonical Goldilocks input words, 1,024 arbitrary raw
compression cases, and 128 compression-witness outputs (32-bit counter subset).

Hash/stream/XOF comparisons apply the same Goldilocks input/output canonicalization
on both sides. The local adapter uses the production std BLAKE3 primitive, but these
are not production Stwo transcript or framed-node benchmarks. The streaming arm
absorbs seven words at a time. Width-eight permute produces 64 output bytes.
The raw compression arm calls our canonical compression author directly.

| Operation | Input bytes | ZisK ns/call | Stwo ns/call |
|---|---:|---:|---:|
| hash_le64 | 0 | 65.49 | 73.33 |
| hash_le64 | 8 | 65.27 | 75.88 |
| hash_le64 | 56 | 65.96 | 80.50 |
| hash_le64 | 64 | 66.28 | 79.54 |
| hash_le64 | 72 | 129.25 | 125.25 |
| hash_le64 | 128 | 129.51 | 125.98 |
| hash_le64 | 1016 | 1016.78 | 807.61 |
| hash_le64 | 1024 | 1016.58 | 806.10 |
| hash_le64 | 1032 | 1136.93 | 916.64 |
| hash_le64 | 4096 | 4234.30 | 3293.74 |
| hash_le64 | 65536 | 68443.67 | 52760.16 |
| stream_xof | 0 | 65.07 | 91.27 |
| stream_xof | 64 | 68.04 | 100.35 |
| stream_xof | 1024 | 1081.90 | 896.11 |
| stream_xof | 1032 | 1142.54 | 945.91 |
| stream_xof | 32768 | 34492.10 | 27107.88 |
| permute8 | 64 | 65.89 | 96.35 |
| compress_xof | 64 | 58.16 | 43.60 |
| compression_witness | 64 | 1108.64 | 2153.26 |

The witness row is **different work with equivalent compression outputs**: peer
`expand_lane` writes its Goldilocks G-band and accumulates lookup multiplicities;
local `compression_witness.prepare` writes full M31 G/XOR rows and routing metadata,
without constructing lookup multiplicities. Both timers also sum emitted trace
values, so different representation sizes affect checksum work. This observation
is not a like-for-like kernel speed ratio, hash-proof benchmark or prover ranking.
It identifies work to split into separately timed emission and counting stages.

The CPU peer source has no ARM SIMD specialization in this scalar comparison;
this does not measure its x86 SIMD or CUDA performance. Current results do not
establish whole-prover superiority or a full hash-proof timing comparison.

`results.json`, `qualification.json`, `run.log` and `provenance.json` retain exact
measurements and binary/source identities. `phase1-source/` freezes the adapters.
The initial local build failed on an inferred narrow loop-count type; the explicit
usize count fixes it. `build.log` retains that diagnostic. Additional completed stages are below. The full remaining function map is in
[CATALOG.md](CATALOG.md); the full campaign is not complete.


## Extended CPU campaign

The first 51 accepted timing cases have matching qualification files recording AC power
before and after the phase and the exact binary hashes. Samples are interleaved,
four per arm, with deterministic checksums and preflight qualifications. Timing
is serialized under the repository build lock. Each C ABI call covers a batch.
Zig ReleaseFast / C++ -O3 use native ARM code generation. C++ OpenMP pragmas are
not enabled: these are explicitly **single-worker portable CPU** measurements,
not Proofman's optimized x86 or CUDA paths. Rust uses release/LTO/native CPU.

Field benchmarks compare **different fields**: GL64 vs M31, cubic GL extension
vs quartic QM31. They are cost observations, not equivalent-security rankings.
Field inverse loops use consecutive nonzero inputs; other field loops use
recurrent outputs. SHA2 0.10.9's ZisK-selected features (`compress`, without `asm`)
select the software ARM SHA path, whereas Zig may use ARM SHA instructions.
Its host SHA speed ratio must not be extrapolated to ZisK on x86 or guest proof.

Transform constructors are timed separately (one setup observation per size/arm
in `stage-qualification.json`). Main forward/inverse loops reuse their plans and
buffers, include the input copy and full output checksum. Both round-trip at every
reported size. Peer LDE internally constructs an extension NTT plan and powers;
our LDE reuses precomputed twiddles. Those are actual API boundaries, not matched
allocation work. LDE is measured as an equivalent stage, not output parity.

FRI uses the actual unmodified peer `FRI<GL>::fold`, step 1, folding factor 2.
The portable CPU implementation constructs an NTT plan inside each fold group;
this is a major contributor to the observed cost. Local uses the CPU backend's
in-place line-fold implementation and a reused workspace. Both include buffer
preparation/checksum; their internal allocation costs remain included. Peer
constants remain constant; local's unnormalized fold doubles them, as its protocol
requires. Constant-polynomial checks pass at all three sizes. **This is not a
matched-security comparison, GPU comparison or whole-recursion speedup.**

The Merkle comparison calls the peer's production `merkletree`, but the local arm
is a research adapter reproducing **the peer protocol**, not our production tiled
builder. Every root matches. Tree buffers are retained, and only the root is
checksummed each repetition. Native node and leaf entries use actual local framed
hash authors; their encodings and digest canonicalization differ from the peer.

Keccak invokes our admitted guest execution authority and the exact `tiny-keccak`
2.0.2 dependency used by ZisK's execution code. Neither timer includes VM dispatch,
witness generation, lookup registration or proving. Rust BLAKE3 calls ZisK's actual
seven-round helper with matching initialization/feed-forward supplied by the harness.

| Operation | Size | ZisK | Stwo | Comparison |
|---|---:|---:|---:|---|
| field_add | 1 operation | 0.70 ns | 0.67 ns | different_fields |
| field_mul | 1 operation | 1.84 ns | 1.55 ns | different_fields |
| field_inv | 1 operation | 57.89 ns | 35.46 ns | different_fields |
| forward_transform | 1024 elements | 16.783 µs | 1.124 µs | goldilocks_multiplicative_vs_m31_circle |
| inverse_transform | 1024 elements | 16.629 µs | 1.189 µs | goldilocks_multiplicative_vs_m31_circle |
| lde_2x | 1024 elements | 58.471 µs | 3.524 µs | goldilocks_multiplicative_vs_m31_circle |
| forward_transform | 16384 elements | 0.3315 ms | 24.271 µs | goldilocks_multiplicative_vs_m31_circle |
| inverse_transform | 16384 elements | 0.3285 ms | 24.518 µs | goldilocks_multiplicative_vs_m31_circle |
| lde_2x | 16384 elements | 1.1517 ms | 73.702 µs | goldilocks_multiplicative_vs_m31_circle |
| forward_transform | 262144 elements | 7.3765 ms | 0.4792 ms | goldilocks_multiplicative_vs_m31_circle |
| inverse_transform | 262144 elements | 7.1457 ms | 0.4744 ms | goldilocks_multiplicative_vs_m31_circle |
| lde_2x | 262144 elements | 26.0381 ms | 1.4681 ms | goldilocks_multiplicative_vs_m31_circle |
| extension_add | 1 operation | 6.76 ns | 1.31 ns | goldilocks_cubic_vs_m31_quartic |
| extension_mul | 1 operation | 8.73 ns | 11.37 ns | goldilocks_cubic_vs_m31_quartic |
| extension_inv | 1 operation | 180.70 ns | 61.11 ns | goldilocks_cubic_vs_m31_quartic |
| batch_inverse | 1024 elements | 4.448 µs | 1.356 µs | different_base_fields |
| binary_merkle_canonical_words | 1024 elements, 64 B/leaf | 0.1318 ms | 0.1452 ms | identical_protocol_peer_production_tree_local_research_tree |
| batch_inverse | 16384 elements | 70.783 µs | 20.800 µs | different_base_fields |
| binary_merkle_canonical_words | 16384 elements, 64 B/leaf | 2.0998 ms | 2.3220 ms | identical_protocol_peer_production_tree_local_research_tree |
| batch_inverse | 262144 elements | 1.3321 ms | 0.3366 ms | different_base_fields |
| binary_merkle_canonical_words | 262144 elements, 64 B/leaf | 33.5797 ms | 37.1929 ms | identical_protocol_peer_production_tree_local_research_tree |
| binary_merkle_canonical_words | 16384 elements, 512 B/leaf | 9.3394 ms | 7.8490 ms | identical_protocol_peer_production_tree_local_research_tree |
| native_node_hash | 1 operation | 63.46 ns | 118.20 ns | different_protocol_framing_and_inputs |
| native_leaf_64_payload_bytes | 1 operation | 68.82 ns | 128.92 ns | different_protocol_framing_and_inputs |
| keccak_f1600 | 200 bytes | 136.77 ns | 4.748 µs | identical outputs |
| sha256 | 64 bytes | 205.53 ns | 32.77 ns | identical outputs |
| sha256 | 1024 bytes | 1.720 µs | 340.47 ns | identical outputs |
| sha256 | 65536 bytes | 0.1035 ms | 21.025 µs | identical outputs |
| zisk_rust_blake3_compression | 64 bytes | 53.22 ns | 43.88 ns | identical outputs |
| fri_fold_2x | 1024 elements | 0.7398 ms | 8.101 µs | different_fields_domains_normalization_and_allocation |
| fri_fold_2x | 16384 elements | 11.8360 ms | 0.1151 ms | different_fields_domains_normalization_and_allocation |
| fri_fold_2x | 262144 elements | 189.5277 ms | 2.1553 ms | different_fields_domains_normalization_and_allocation |


## What to investigate from these results

- **Keccak execution**: the largest identical-function gap favors ZisK's tiny-keccak
  path (~35x). Inspect fixed-round/lane scheduling and generated code, then measure
  its contribution to execution and witness time before claiming CSP savings.
- **Small BLAKE3 messages / native frames**: peer's short canonical-word tree is
  ~10% faster; our larger leaves are faster. Our native 92-byte node frame takes two
  compression blocks versus the peer's 64-byte input. Explore prefix/state reuse
  and batched compression while preserving the authenticated frame bytes.
- **Hash witness and lookups**: the original lane probe is insufficiently matched
  to rank the complete pipelines. Split emission, boundary work, and counters next.
- **Arithmetic/transform/FRI**: current ARM figures do not show a local core-field
  or transform disadvantage that explains the tens-of-seconds recursive proof.
  Profile complete AIR, commitments, witness and scheduling; do not extrapolate
  primitive wins to that latency.

## Qualification and limits

- 6,000 base-field checks against Python modular arithmetic.
- 3,072 extension operations checked using independent polynomial/tower arithmetic
  and multiplicative inverse identities.
- Forward/inverse round trips at 1,024 / 16,384 / 262,144 elements on each arm.
- Full Merkle root parity at all four tree shapes.
- 256 full Keccak states, 256 Rust-helper BLAKE3 cases, and nine SHA256 cases checked
  against both implementations / Python hashlib, in addition to phase 1's checks.
- Six constant-polynomial FRI checks, respecting each protocol's normalization.
- No whole proof, ECDSA peer, full lookup pipeline, or CUDA comparison is claimed.

Two harness qualification failures were caught and fixed before accepting the
associated data: an NTT extension plan that intentionally ignored the upper half
of a general input, and an inferred narrow Zig byte-count multiplication at a
512-byte leaf boundary. Rejected logs are retained. Current timing results were
rerun with the corrected adapters. Peer cryptographic source was not modified.

## Native transcript and PoW: completed battery run

On the user's instruction to proceed, the runner rechecked power; the host still
reported battery at 99%. The four remaining cases were run with an explicit
`--allow-battery` option and retained separately under `battery-protocol/`.
Both implementations used the same host, binaries and interleaved sample sequence.
Power remained battery before/after and at every case boundary. These observations
are **not pooled with the earlier AC results**; an AC repeat remains outstanding.

| Native operation | Absorbed payload | ZisK | Stwo |
|---|---:|---:|---:|
| Absorb + eight scalar extension-field draws | 64 B | 0.251 µs | 1.279 µs |
| Absorb + eight scalar extension-field draws | 1,024 B | 1.264 µs | 2.750 µs |
| Absorb + eight scalar extension-field draws | 32,768 B | 37.271 µs | 51.473 µs |
| PoW candidate evaluation | one candidate | 62.922 ns | 22.099 ns |

These are **different native protocols**, not byte-identical computations or
whole proof speedups. Transcript inputs have equal payload byte lengths but use
GL64 versus u32 encodings and different framing. Eight peer draws produce 24
GL64 words (192 bytes); eight local scalar draws produce 32 M31 words (128 bytes).
Peer TranscriptGL absorbs a stream and caches XOF output in eight-word blocks;
local `drawSecureFelt` hashes a fresh framed draw on every call. Peer transcript
construction performs its native small allocations within each timed iteration;
local channel initialization is inline. Local batched `drawSecureFelts` is not
measured here and must not be conflated with the scalar-draw API.

PoW measures fixed candidate throughput, **not time to solve 26-bit PoW**.
Local calls the production four-lane candidate kernel with a reused chaining
value and a 26-bit protocol prefix; peer uses its canonical-word `permute8`
nonce construction. Peer checksums a 64-bit output word; local checksums a 32-bit
word. The peer's four 12-bit minimum-nonce checks are qualification only, not a
canonical-parameter proof benchmark. No linear projection to E2E time is claimed.

All checks passed again: 35 canonical XOF comparisons, 1,024 scalar/batched PoW
checks and four minimum-nonce checks against the independent std BLAKE3 adapter.
Four timed samples per arm per case are retained with binary identities. The C++
transcript link includes unmodified legacy implementations to satisfy its runtime
switch, but selects BLAKE3 explicitly; unexpected logging/exit hooks abort.

Reproduce this separately labelled run, or omit the flag to require AC:

```sh
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_protocol.py --allow-battery
python3 autoresearch/notes/2026-09-24-zisk-component-suite/summarize.py
```

All harnesses live in this note directory; local C ABI roots are under
`src/frontends/riscv/zisk_*_benchmark.zig` and
`src/prover/zisk_protocol_benchmark.zig`. They are not wired into the prover build.
`build_stages.py`, `build_more.py`, `build_primitives.py`, and `build_fri.py` reproduce
the subsequent builds; corresponding `run_*.py` files reproduce their phases.
The Rust helper source points at the pinned checkout; Cargo.lock fixes dependencies.
The phase-1 build commands are in `BUILD.md`.

`campaign-results.json` records **51 AC cases and four separate battery cases (55 total)**. `summarize.py` rejects
missing qualification files or mismatched binary hashes. `local-source.tar.gz`
freezes the dirty working-tree source dependencies (2,815 Zig files plus the build
lock helper); `campaign-provenance.json` records the host and both clean peer pins.
