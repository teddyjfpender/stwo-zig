# Kona OP execution: measured RV64 implementation

2026-11-06. This is execution evidence, **not an OP validity proof or a GPU
throughput result**. No SNARK wrapper, SP1 runtime or unconstrained execution is
used. The baseline is our software RV64 Kona guest, not SP1 or ZisK.

## Four-block range

Real OP Sepolia blocks 26207960–26207963; 22,094,683 execution gas. Every result
matches the upstream fixture's computed block hashes, native eager/lazy
execution, production RV64 execution and independent Unicorn 2.1.4 execution.
The independent oracle checks exact termination at N instructions (N−1 then 1),
all 32 registers, PC, all 43 output bytes and service counts. The final baseline
and two final candidates use the existing production diagnostic executable.

| Variant | Instructions | Instructions/gas | Reduction vs software |
|---|---:|---:|---:|
| Software | 1,017,752,110 | 46.0632 | — |
| Sponge + secp services, upstream Revm/MPT | 211,902,882 | 9.5907 | 4.80× |
| Existing optimized Revm, thin LTO, upstream MPT | 196,637,433 | 8.8998 | 5.18× |
| Same, full LTO | 193,391,676 | 8.7529 | 5.26× |
| Capped MPT reference length | 168,138,862 | 7.6099 | 6.05× |
| Bounded single-pass MPT encoding | **167,137,833** | **7.5646** | **6.09×** |
| Optional existing bulk-memory services | **151,104,964** | **6.8390** | **6.74×** |

The MPT algorithm alone removes 13.58% of instructions versus the same full-LTO
guest with upstream MPT. The native semantic reference retains upstream MPT.

**These are not GPU speedup factors.** Service work is not free. On the final
production diagnostic, bounded MPT uses 1,464,594 service RAM word transitions;
the bulk-memory candidate uses 12,145,329. Both have the same crypto call counts.
Bulk memory remains an explicit experimental feature; it is not the recommended
default until full native/recursive GPU proofs establish the tradeoff.

| Isolated block | Gas | Software instructions | Bounded MPT | Bulk memory |
|---|---:|---:|---:|---:|
| 26207960 | 953,624 | 76,973,388 | 9,189,252 | 8,027,512 |
| 26207961 | 5,516,493 | 409,596,447 | 74,442,875 | 68,126,238 |
| 26207962 | 11,822,253 | 409,708,421 | 60,790,803 | 55,039,462 |
| 26207963 | 3,802,313 | 195,718,044 | 24,170,698 | 21,542,348 |

The range shares authenticated preimages and retains Kona's updated trie in one
builder. Its packed input is 2,237,844 bytes with 4,018 preimages. The isolated
inputs total approximately 3.10 MB. Unused lazy preimages are never returned;
every used preimage is authenticated before access and only then memoized.

## What changed

- Added a pinned no_std Kona executor and a separate upstream native reference.
  RocksDB stays on the fixture-import host. Complete payload attributes use a
  binary representation, borrowed sorted full-hash preimages and bounded counts.
- Reused existing allocator, single-thread atomics, RV64 machine transport,
  constrained Keccak sponge/secp and optimized Revm. No OP-specific VM or crypto
  executor was introduced. Bulk memory is optional.
- Replaced repeated exact subtree sizing with an exact inline/hashed threshold
  walk, then bounded branch/extension encoding. There is no mutable trie cache
  or invalidation policy. Independent byte-building tests check full encodings
  and roots, including threshold/path boundaries and general fallbacks.
- Added real-fixture benchmarking, independent execution checks, malformed-input
  controls, fixed-geometry capture scheduling comparisons and portable inputs
  for the existing resident GPU producer. Deployment policy comes from an
  explicit resident manifest; the package makes no capacity claim.
- Fixed the native GKR tool's build ownership so it receives its required circuit
  integration imports. The complete native GKR executable now builds.

## Capture and validation

The complete first block (final memory candidate, 8,027,512 instructions) was
captured through the actual producer with 262,143-step batches. Serial capture
and checkpoint/replay with 1 and 2 workers produced **identical captured-value
digests**. Measured peak child RSS was 1,995,014,144 / 2,024,185,856 /
2,039,263,232 bytes respectively. This is Linux `wait4` RSS, not a memory cap.
It excludes native proof generation and GPU resources. See `capture.json`.

An earlier 4M-step, two-worker capture was killed with exit 137 while several
heavy compilers were running. Smaller bounded capture completed; the failed run
does not establish a VRAM limit or qualify the default 4M proof geometry.
The committed native geometry plan is explicitly for the earlier 8,276,623-step
memory candidate, not the final binary; its context file pins that request.

Validation records:

- 14 execution/metadata/witness/sponge tests passed.
- 15 offline MPT tests passed, including original Alloy HashBuilder insert/delete
  properties at `PROPTEST_CASES=64` and independent byte-level tests. Two original
  live RPC tests are explicitly excluded; they were not run.
- 9 Python boundary/packaging tests passed.
- A used parent-state preimage mutation, wrong computed-block claim and invalid
  reserved header were rejected by native eager/lazy execution and trapped in
  the real RV64 guest before output publication. Outer SHA pins were deliberately
  recomputed so these test guest validation rather than only file identity.
- All eight pinned upstream OP Sepolia execution fixtures passed RV64/oracle
  comparisons with the capped MPT candidate. The four default fixtures also pass
  the final bounded encoder and optional bulk-memory candidate. See the extra
  fixture records for the final bounded encoder's larger-block checks.
- Rust formatting of owned packages, Ruff and whitespace checks passed. The
  repository-wide source-conformance inventory has existing baseline failures;
  it is not represented as a passing gate.

Native wall times were collected while compilers and other benchmarks were
active. They are not used to claim a speedup, predict GPU time or compare SP1.
The fixtures are OP Sepolia historical executor fixtures, not modern OP Mainnet,
Base, blob derivation or adversarial precompile coverage.

## Files and reproducibility

Start with [`opstack/README.md`](../../../../opstack/README.md). `fixtures.json`
pins the eight upstream archives by full SHA256 and size at Optimism commit
`a271fd6b3feb76e49f3453e5a27be4b33a3c7211` (peeled Kona v1.8.0).
The pinned compiler is nightly-2026-08-08; Zig is 0.15.2.

- `benchmarks.tsv` / `benchmarks.json`: 35 default-case ablation measurements.
- `execution-evidence.json`: native results, machine/oracle registers and counts,
  exact ELF/input identities and expected outputs; no proof receipts.
- `source-snapshots.json`: source snapshots at each historical experiment. These
  include tooling revisions and deleted intermediate files; they are not all
  the final source tree. No instruction result is relabeled as a different ELF.
- `memory-build.json`: final memory build recipe and source/binary identities.
- `capture.json`, `native-plan-*.json`: complete capture and earlier geometry
  diagnostic, with their distinct identities.
- `rejections.json` and test logs: actual validation outcomes.

Large preimages and ELFs are regenerated, not checked in. The build helper was
smoke-tested end to end; the capped-MPT frontier ELF was byte-identical to the
same candidate rebuilt through the helper in this checkout.

## Remaining gates

There is no GPU or authenticated GPU endpoint in this workspace. **No OP native
proof, recursive root, GPU timing, VRAM fit or independent proof reception was
produced here.** Input packages and diagnostic geometry do not stand in for them.

Replacing SP1 for OP validity still requires authenticated Kona L1 derivation and
blob/KZG validation, an execution/derivation bind on the same payload commitment,
anchored L1/reorg handling and a running accumulator. Settlement requires STARK
compression and a direct on-chain STARK verifier. No SNARK wrap is planned.
The inherited conjectured 128-bit native profile is not a whole-protocol security
certificate. These remaining jobs are not represented by a dummy success flag.
