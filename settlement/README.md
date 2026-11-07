# Stwo settlement verifier components

This directory contains Solidity verification for compressed Stwo lifted BLAKE2s
openings and the native proof-of-work and query stage, plus a stateful checkpoint
contract for the eventual complete Kona transition verifier. The two interfaces are deliberately separate. The opening
verifier authenticates rows against a supplied root. The checkpoint advances
only through its immutable transition verifier, which must verify derivation
and execution under the configured rollup rules.

The [pinned prior art](https://github.com/neotheprogramist/stwo-sol-verifier/tree/c2547d152a4b717469476767e53d5cd3a4ddb69d)
uses a Keccak channel and QM31. The Kona artifacts here use OM31, a raw
BLAKE2s transcript, a prefixed lifted BLAKE2s VCS and local GKR. A byte
adapter cannot reconcile those protocol differences. The prior art also
stores temporary verifier data in contract storage. This implementation
uses calldata and memory for proof data and reserves persistent storage for
accepted checkpoints.

## Tests and gas

With Node.js 22 or newer, run from this directory:

```sh
npm ci
npm test
SOLAR=/path/to/solar npm test
```

The suite compiles through standard JSON, starts a fresh local Anvil, and
checks independent BLAKE2s parity, malformed multiproofs, two mainnet
worker openings, state persistence, stale proofs and cross-instance replay.
The test-only transition backend exercises statement binding and storage.
It does not implement a Kona verifier. No network deployment is required.

The default compiler is solc 0.8.30 with via-IR, Shanghai bytecode and
100,000 optimizer runs. The same suite runs with Solar 0.3.0, which can be
installed using the [Solar release instructions](https://github.com/paradigmxyz/solar/tree/v0.3.0).
Use the compiler's emitted runtime bytecode for size and gas comparisons.
The benchmark transactions include intrinsic and calldata gas.
Anvil's elevated test gas limit allows the separate-path comparison.

The initial opening-only measurements provide a historical baseline.

| Compiler | Worker | Queries | Compressed gas | Separate-path gas | Reduction | Runtime bytes |
|---|---|---:|---:|---:|---:|---:|
| solc 0.8.30 | truth-3 | 102 | 8,194,326 | 19,677,339 | 2.40× | 4,948 |
| solc 0.8.30 | truth-4 | 99 | 7,853,066 | 19,099,986 | 2.43× | 4,948 |
| Solar 0.3.0 | truth-3 | 102 | 10,292,733 | 24,478,503 | 2.38× | 3,186 |
| Solar 0.3.0 | truth-4 | 99 | 9,863,685 | 23,760,618 | 2.41× | 3,186 |

The separate-path baseline uses the same optimized hash and the same
opened rows. It reconstructs each branch independently in one test
transaction. It is not a benchmark of the Keccak prior art. On solc,
the tuned fixed round schedule and optimizer settings reduce the
compressed gas by roughly 16% versus the loop schedule at 200 runs.
Solar produced a smaller opening verifier but used more gas on these
calls, so solc is the gas benchmark default. The [raw counters](fixtures/gas-benchmark.json)
also record the single-opening and mock-checkpoint transactions.

The gain comes from reusing branch hashes across queries, precomputing
the state after each 64-byte domain prefix, and evaluating four BLAKE2s
G lanes in parallel. The proof wire carries rows and siblings in calldata.
The verifier reuses two memory arrays as it walks up the tree. The
positions must be sorted and unique, with exactly one row per position.
Sibling hashes are consumed in increasing index order at each level,
starting at the leaves. Rows are the Stwo commitment's little-endian
M31 words in commitment column order.

## Native query binding and shared roots

`NativeQueryOpening` uses the native 20-bit PoW and 108-query profile. It
verifies each nonce against its pre-PoW transcript digest, mixes the
nonce, and derives all query words. It preserves the native even/odd
coset bit when projecting into a tree of a different height. Every
derived position must appear in the sorted calldata set, and every
supplied position must be derived. For workers with the same authenticated
root and tree geometry, a single compressed opening can cover their
union.

The root, domain sizes and pre-PoW digests come from the surrounding
verifier. The contract does not derive or authenticate that earlier
transcript. Its return value is an opening check and cannot authorize a
checkpoint. The tests exercise replay across workers, missing and surplus
rows, changed nonce, digest and domain, modified row data and failure to
advance when an opening checker is installed as the checkpoint backend.

| Solc 0.8.30 on block 121057303 | Gas | Sibling hashes |
|---|---:|---:|
| Two query-bound openings | 16,143,948 | 538 |
| One shared-root query-bound opening | 13,234,957 | 367 |

The shared call covers 194 distinct rows and reduces gas by 18.0%.
Unrolling message loading and digest encoding also reduces the two
opening-only calls to 7,641,890 and 7,323,662 gas, about 6.7% below the
initial measurements. Solar's shared call uses 17,340,129 gas. It
passes with the elevated local limit and exceeds the EIP-7825 cap.
See the [query benchmark receipt](fixtures/query-gas-benchmark.json).

The next BLAKE2s optimization swaps byte order across whole EVM words
before loading the message schedule and when encoding the digest. It
preserves the native BLAKE2s digests and opening wire format. On the
same 194-row OP Mainnet fixture, solc shared-root gas drops from
13,234,957 to **12,176,569** (8.0% less), while runtime bytecode grows
from 7,465 to 10,214 bytes. The opening-only calls now cost 6,998,420
and 6,707,063 gas. The receipt keeps the earlier measurements for
comparison.

Run the shared-root check under Osaka's transaction cap with:

```sh
npm run test:osaka
```

The SMT checks cover the packed 32-bit additions and rotations, query
projection parity and range, the exact-set bitmask, and the in-place
Merkle write bound. These are local invariants, separate from end-to-end
proof soundness and contract review.

```sh
python3 -m pip install z3-solver==4.15.4.0
python3 tools/check_invariants.py
```

## Native DEEP and FRI transcript suffix

`NativePcsTranscript` reconstructs the native DEEP challenge, each FRI
folding challenge and the pre-PoW digest for the b2/q108/p20/fold4 profile.
It absorbs canonical little-endian OM31 samples, mixes roots in native
order and validates the layer count and final polynomial size. In this
profile `b2` means a blowup factor of two (`log_blowup_factor = 1`). The
caller owns the OODS prefix, sample count and domain. This suffix is
available to a future full verifier alongside the existing query checks.
The checkpoint still has no complete transition backend.

The tests compare digest and challenge bytes with Node's independent
BLAKE2s at multiple block boundaries, reject malformed field and layer
encodings, and rerun the real Mainnet commitment opening tests.

`NativeFriFold` evaluates the native unnormalized OM31 butterflies for
2, 4, 8 or 16 values. Its test uses independent quadratic tower arithmetic.
The surrounding verifier still needs to derive the coordinates from the
query positions, authenticate the opened subgroup, connect each fold to
the next layer and check the final polynomial.

The Solidity suite also replays the 5,532 samples, three FRI roots and final
coefficient of `truth-4.bin` from the accepted block 121057303 bundle. The
reconstructed digest matches the native PoW/query fixture. This case uses
an elevated local gas limit and a prefix captured from the native receiver.

To reproduce, apply `tools/native-pcs-capture.patch` in a disposable worktree,
use `STWO_EXPORT_PCS_SUFFIX=1` in the native receive command below and set the
request's proof workers to one for contiguous capture records. Run:

```sh
python3 tools/export_pcs_suffix.py pcs.log receive.json \
  fixtures/native-queries-121057303.json truth-4.bin \
  fixtures/native-pcs-121057303-truth-4.json
```

## Mainnet provenance

The fixtures come from `truth-3.bin` and `truth-4.bin` of the complete
native Kona proof for OP Mainnet block **121057303**, benchmarked on
[`2fe577d6e`](https://github.com/teddyjfpender/stwo-zig/commit/2fe577d6e82dd200430912f6ea36d19c35dadea3).
The fresh native receiver accepted all three CPU and seven service
proofs. Its receipt is checked in alongside the openings. Each fixture
identifies its source worker by SHA-256 and records the root and original
compressed sibling vector offsets. Both openings use a shared
four-column commitment and different query sets. The Solidity tests
reconstruct paths with Node's independent BLAKE2s before checking the
contract and mutating both a row and a sibling.

To extract from the original bundle or regenerate equivalent fixtures
from a fresh bundle, apply `tools/native-opening-capture.patch` in a
disposable worktree at the source commit and build the native receiver.
The patch is diagnostic only and is not applied to the repository's prover.

```sh
git apply --unidiff-zero /path/to/settlement/tools/native-opening-capture.patch
zig build rv64-word16-ethereum-native -Doptimize=ReleaseFast -j1
STWO_EXPORT_SETTLEMENT_OPENINGS=1 STWO_ZIG_RV64_SETUP_BUILD_THREADS=1 \
  zig-out/bin/rv64-word16-ethereum-native \
  --security-profile conjectured128_b2_q108_p20_fold4 \
  verify-candidate "$REQUEST" "$BUNDLE" 2147483648 6442450944 \
  > receive.json 2> openings.log
python3 /path/to/settlement/tools/export_opening.py \
  openings.log "$BUNDLE/truth-3.bin" truth-3-opening.json --block 121057303
```

Use only diagnostics from a successful complete native receive. The
exporter checks the original witness against the worker bytes and
independently recomputes the commitment. It can also export smaller
query subsets using `--queries`. See the [Kona runbook](../opstack/README.md)
for native proof generation.

To capture the pre-PoW state, apply `tools/native-query-capture.patch` in
a disposable worktree, rebuild the receiver, and run the same command
with `STWO_EXPORT_SETTLEMENT_QUERIES=1`. After native acceptance, run
`tools/export_queries.py` with the diagnostics log, output JSON path, and
the two opening fixtures. The exporter uses Python BLAKE2s to check each
nonce and match the exact projected query set to its worker.

## Checkpoint authority and remaining verifier work

`NativeFriFold.foldCanonical` checks each inverse against the canonical M31
circle or line domain at the bit-reversed query position. The circle round
uses y, projects onto the same half-coset, then uses x for the line rounds.
The tests exercise independent coset enumeration with challenges from the
mainnet transcript and reject modified inverses, an out-of-range query and a
substituted layer kind. The surrounding verifier must supply authenticated
queries, layer geometry and opened evaluations before calling the fold.

`KonaCheckpoint` pins a rollup ID and configuration, the transition
verifier address and its runtime code hash, and the initial height and
output root. Advancement requires the next consecutive height and a recent
canonical L1 anchor. The checkpoint must run on the settlement L1. It
authenticates the anchor number and hash with `BLOCKHASH`, which
exposes the 256 preceding blocks. Expired anchors require a fresh
statement and proof. The statement digest binds the settlement chain
ID, contract, rollup configuration, previous and next checkpoints, L2
origin, and L1 anchor. The transition verifier must prove that the
origin and derivation data are authenticated by that anchor. The L2
origin can precede the anchor. Writes occur after proof verification.
Deployments require a standalone,
non-upgradeable backend with the intended verification key and a trusted
initial checkpoint. Pinning a proxy's runtime hash would not pin its
implementation.

The fixtures exercise commitment openings from a verified proof. Full
Kona verification on the EVM still requires reconstruction of the earlier
Fiat–Shamir transcript, GKR, OODS, FRI folding and verifier-owned AIR, plus authenticated L1 derivation and
binding to the OP output root. The checkpoint's mock tests establish
storage behavior only. There is no production transition backend here.

The benchmark bundle contains 33,596,418 bytes of native binaries.
Even charging only four gas per byte would exceed 134 million gas
before verifier execution. That exceeds the [EIP-7825 transaction cap](https://eips.ethereum.org/EIPS/eip-7825).
A production design needs a compact recursive STARK or a deliberately
segmented verifier. A recursive route can use an EVM-friendly outer
transcript while preserving the native suite in the inner proofs. The
full-verifier 10× target needs an equivalent statement, security profile
and proof format on both sides of the measurement.
