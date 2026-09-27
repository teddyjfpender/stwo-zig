# Ethereum block proving delivery

Goal started 2026-09-24T19:50:26+00:00; requested nine-hour window ends 2026-09-25T04:50:26+00:00.
Keep the full objective active until verified: authenticated full Ethereum block
execution, efficient precompiles, recursive completion, materially lower memory,
and a path to GPU block proving. Authentication-only workloads are not completion.

## Completion evidence required

1. Execute the pinned mainnet 24,628,607 stateless-validator guest and compare
   its 43-byte public result to the independently retained host oracle.
2. Prove all execution segments with the canonical BLAKE3 path, q70/PoW26,
   authenticated precompile memory linkage, correct continuation boundaries,
   and no omitted instructions or trusted host results.
3. Recursively aggregate all segments, authenticate any padding, independently
   verify the final root and bind ELF/program, input, output, execution span,
   and independently admitted verifier keys.
4. Integrate efficient SHA-256, Keccak and elliptic-curve operations, including
   guest dispatch, witness/AIR, lookup/caller/memory relations, key identities,
   and adversarial verification. Inventory other Ethereum precompile needs.
5. Demonstrate bounded scheduling and memory at growing workloads, with worker
   and process memory reported separately. Avoid retaining all witnesses or
   child captures. Do not claim GPU VRAM requirements from CPU RSS.
6. Derive implementation choices from pinned ZisK code, including polynomial
   operations, commitments, scheduling and transfers. Preserve attribution for
   any copied code and verify field/commitment semantics before porting.
7. Evaluate cuda-metal for applicable CUDA kernels. GPU execution remains
   unqualified without a real backend run; CPU delivery cannot establish it.
8. Retain artifacts, exact source/binary/input identities, tests and actual
   proof verification. Do not mark completion from passing microbenchmarks.

## Current authoritative starting points

- Full guest: `autoresearch/benchmarks/guest_runtime/ethereum`, pinned unmodified
  stateless-validator-reth with native Keccak and transaction signer recovery.
- Block and witness contract: `autoresearch/benchmarks/ethereum_block_mainnet_24628607.json`.
- Existing block product still includes earlier versioned/legacy routes; audit
  the production route rather than infer readiness from its executable name.
- Canonical BLAKE3 authentication plus recursive wrapper qualifies 1/16/32/64
  transactions. This is not full block execution or aggregation of a block.
- SHA fixed-pair direct candidate exists but explicitly lacks CPU dispatch,
  memory relation and production admission. Revm precompiles remain software.
- Native BLAKE3 tree nodes enforce independently admitted keys and Span binding.
  Folds require equal-height adjacent slots; non-power-of-two jobs need verified
  empty padding, not a host-only root assembly.

## Work sequence

First connect a bounded streaming recursion frontier to real verified nodes and
persistent workers, then a full-guest segmented producer/verifier entry point.
In parallel as engineering tasks (not competing heavy host runs), inventory and
implement the SHA compression/guest linkage using existing typed infrastructure,
then EVM crypto dispatch and missing functionality. Run the real block early
so evidence, rather than benchmark surrogates, determines the remaining work.
Profile and reduce preparation/commitment peaks while preserving proof checks.

## Peer references

Local ZisK checkout: `/tmp/stwo-recursion-peer-research-20260921/zisk`, commit
`5c5f81c96929abed88894473ec6060b1b545b5c5`.
Inspected `recurser/src/prove/command.rs` (persistent registration and independently
validated setup), `precompiles/sha256f/src/lib.rs` (compression-level operation).
Upstream: https://github.com/0xPolygonHermez/zisk
Requested translation tool: https://github.com/Lulzx/cuda-metal
These are design references, not evidence of compatibility with M31/Stwo.

## Current work

Added `blake3_stream_frontier.zig`: logarithmic retained verified subtrees,
ordered admission, checked parent statements, transactional carry-chain failure,
and explicit verified padding. Unit tests exercise ownership and Span semantics;
real proof integration and block execution remain required.
