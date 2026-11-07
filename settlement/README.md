# Stwo settlement verifier components

This directory contains a Solidity verifier for compressed Stwo lifted BLAKE2s
openings and a stateful checkpoint contract for the eventual complete Kona
transition verifier. The two interfaces are deliberately separate. The opening
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

## Checkpoint authority and remaining verifier work

`KonaCheckpoint` pins a rollup ID and configuration, the transition
verifier address and its runtime code hash, and the initial height and
output root. Advancement requires the next consecutive height and a
proof over a statement digest binding the settlement chain ID, contract,
configuration, previous and next checkpoints, and L1 origin. Writes occur
after the verifier returns true. Deployments require a standalone,
non-upgradeable backend with the intended verification key and a trusted
initial checkpoint. Pinning a proxy's runtime hash would not pin its
implementation.

The fixtures exercise commitment openings from a verified proof. Full
Kona verification on the EVM still requires Fiat–Shamir, GKR, OODS, FRI
folding and verifier-owned AIR, plus authenticated L1 derivation and
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
