# OP Stack execution implementation contract

**Mainnet CPU continuation (2026-11-06):** six historical OP Mainnet cases now
match native/RV64/Unicorn execution, and mainnet blocks 120794432 and 121057303 have complete
native CPU STARK bundles with fresh reception and proof-corruption rejection.
The branch is rebased onto GPU `bf2b6c072d51341f1c733f05f870d70b4c15834b`.
Use the [current runbook](../../opstack/README.md) and
[mainnet measurements](../../vectors/reports/rv64-opstack-mainnet-20261106/README.md).
The initial checkpoint below is historical; L1 derivation/binding, recursive
closure and settlement remain open, with no SNARK wrapper.

## Initial checkpoint (historical)

2026-11-06. Initial implementation/measurement GPU base:
`577433230cff23cc26d8e0337e7507dc44ed83af`. Final PR rebase target:
`6d0d1e56a9d3c2f58a2cb035343fd3c643acffc5` (M8 memory-plan/native-producer integration).
The final rebase was completed through GitHub after the execution environment
became unavailable; upstream changes were disjoint from the OP files. These
measurements predate that final GPU-only rebase; no new GPU qualification is claimed.
The M8 job provider remains explicitly unpromoted/fails closed at that target;
the existing resident producer is the execution handoff used by this work.

Build a separate no_std Kona execution guest against Optimism
`a271fd6b3feb76e49f3453e5a27be4b33a3c7211` (peeled `kona-client/v1.8.0`).
It executes OP payload attributes with upstream `StatelessL2Builder`, not the
Ethereum guest's rules. No SP1 runtime, unconstrained execution, or SNARK wrap.

The initial milestone is execution, not derivation or settlement. The statement
commits the rollup configuration, parent header, ordered payload attributes and
computed block hashes. Payloads supplied by a host are NOT evidence of L1
availability, sequencing validity or deposit completeness. A subsequent Kona
L1 derivation proof must bind exactly the same payload commitment before this
can become an OP validity proof.

One range uses one stateless builder and shared authenticated preimage table.
The builder retains the updated trie between adjacent blocks. This avoids
reconstructing the execution database and re-decoding common trie paths for
every block. Input is bounded to 16 MiB, 32 blocks and 131072 preimages.

The wire has a versioned header, postcard metadata, sorted fixed-width key /
offset / length descriptors, then contiguous payload bytes. Offsets must be
canonical, keys strictly increasing and the final offset equal to input length.
The immutable bytes remain borrowed. Preimage Keccak hashes are checked on first
access, before returning bytes, with one bit per record retained in a guest-local
validation bitmap. Missing or mismatched values fail closed. Only successful
validation sets a bit. An eager mode is the semantic reference; it hashes every
record on admission. No preimage is accepted because the host says it is valid.

The execution result digest is a new domain. The guest publishes the existing
43-byte machine transport: digest[32], success=1, chain-id u64le, schema bytes
`OP` (0x504f). The Ethereum guest uses a different schema and digest domain.
This reuses the proven terminal-width contract without changing a constraint or
calling the result an Ethereum SSZ statement or SP1 BootInfo. All 43 bytes and
the exact ELF/input hashes remain independently pinned in the receiver config.
The full 256-bit digest is retained; there is no SNARK-field mask.

`benchmark.py` emits explicit `*-proof-config.json` requests for the existing
native/recursive GPU producer. An execution receipt is not a GPU qualification:
physical OP proofs, independent native/recursive reception, real L1 derivation,
and pure-STARK settlement must still be measured and admitted separately.

Ownership: metadata and bitmap are guest-owned; preimage payloads are borrowed
from immutable input. Native host filesystem/fixture conversion stays outside
the no_std library. No RocksDB or RPC client enters the guest. Failed calls
publish no successful halt/output. Cold parse/hash/setup and execution are
reported separately. Stage medians are not added to derive request medians.

Parity gates: upstream fixture block hashes, eager/lazy output identity, range
versus isolated output identity, host versus RV64 digest and instruction count,
malformed wire and preimage mutation rejection. Pure STARK recursion is inherited
from the GPU base but full OP binding and on-chain STARK verification remain open.
