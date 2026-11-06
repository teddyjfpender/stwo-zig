# Kona on the RV64 proving stack

This is a runnable OP execution guest, not a completed OP validity prover. It
executes real OP Sepolia blocks with pinned Kona, checks every resulting block
hash against an independent upstream fixture, and emits requests for the existing
native/recursive GPU pipeline. It uses no SP1 SDK or SNARK wrapper.

## Build and measure

Requirements: Rust `nightly-2026-08-08` with `rust-src`, Zig 0.15.2, Python 3.12+.
The optional independent execution oracle is pinned to Unicorn 2.1.4. RocksDB is
used only to import the upstream host fixtures, never in the guest.

```sh
rustup toolchain install nightly-2026-08-08 --profile minimal --component rust-src
python3 -m pip install -r opstack/requirements-host.txt
python3 opstack/prepare_fixtures.py --output /tmp/kona-fixtures
python3 opstack/build.py --variant software --artifacts /tmp/kona-software
python3 opstack/build.py --variant frontier --artifacts /tmp/kona-frontier
python3 opstack/benchmark.py --fixtures /tmp/kona-fixtures \
  --artifacts /tmp/kona-bench --host /tmp/kona-frontier/host \
  --guest /tmp/kona-frontier/guest.elf --runner /tmp/kona-frontier/rv64-execution \
  --profile ethereum_services_v3 --oracle
```

`software`, `keccak`, `services` and `sponge` retain the upstream EVM/MPT source.
`lean` additionally uses the existing optimized Revm interpreter/bytecode crates
and the local capped-length MPT change. `frontier` is that guest with full LTO.
`memory` additionally enables the existing constrained bulk-memory services.
All choices are explicit. A lower guest instruction count is not a measured GPU
speedup: service calls, permutations and bytes remain proving work.

The native reference uses the upstream Kona MPT. Each measured RV64 case must
match its output and the fixture's block hashes. The optional independent oracle
checks completion at exactly N instructions (N-1 then 1), all 32 registers, PC,
43 output bytes and service counters. The production RV64 diagnostic is reused;
there is no OP-specific implementation of the VM or crypto executor.

## Architecture

| Location | Responsibility |
|---|---|
| `kona/src/witness.rs` | Borrowed sorted preimage table; canonical bounds/offsets; authenticate each used Keccak preimage before access; a validation bitmap avoids repeated hashing. |
| `kona/src/metadata.rs` | Complete binary payload attributes, RLP parent header, bounded range and canonical rollup configuration; public payload commitment. |
| `kona/src/execution.rs` | One pinned Kona stateless builder per range; retains the updated trie between adjacent blocks. |
| `kona/guest` | RV64IM runtime, existing allocator/atomics/memory ABI, explicit constrained crypto features, OP output schema. |
| `kona/lean` | Separate dependency/optimization policy; no change to the reference host. |
| `kona/vendor/kona-mpt` | Pinned source with capped RLP reference sizing, source hashes and byte-level differential tests. |
| `prepare_fixtures.py` | SHA-pinned upstream fixture import, separate from guest execution. |
| `build.py`, `benchmark.py` | Reproducible binaries, receipts, native/RV64/oracle comparisons and proving requests. |

Inputs are capped at 16 MiB minus the transport length, 131,072 preimages and 32
blocks. Keys are full 256-bit Keccak hashes. Descriptors are strictly ordered and
payloads contiguous: aliases, duplicates, gaps and trailing bytes are rejected.
Missing or incorrect used preimages fail before data reaches Kona. Metadata
range counts are checked during deserialization before allocating the sequences.
The native reference and guest share execution semantics but have independent
machine backends; real fixture hashes provide an external result reference.

The MPT optimization changes no mutable trie representation or invalidation
policy. A child with RLP length >=32 is represented by a 33-byte hash reference.
Computing that predicate does not require the exact length of its full subtree.
The bounded walk stops as soon as a list payload reaches 31 bytes. Exact inline
lengths below the threshold, full encodings and commitments stay unchanged.
Branch/extension hashing also writes their bounded reference encodings once
into a 564-byte stack scratch, avoiding a heap buffer and sizing walk. Arbitrary
leaf values and nonstandard branch lengths retain the general encoding path.
`UPSTREAM.json` records every original source hash. Original offline trie tests
and new independent byte-building reference tests cover this change. Two original
RPC-dependent tests are explicitly excluded from the offline gate.

## Statement and the GPU boundary

The payload commitment is SHA256 over the `stwo/opstack/payload-range/v1` domain,
the canonical rollup-config hash, parent-header hash, count and length-prefixed
binary payload attributes. It excludes expected execution hashes: derivation
must be able to commit the same inputs without executing the EVM.

The result digest uses `stwo/opstack/execution-range/v1`, the payload commitment
and the ordered computed block hashes. The guest publishes the existing 43-byte
machine transport: digest[32], success=1, chain-id u64le, schema bytes `OP`
(0x504f). It is a distinct execution statement, not Ethereum SSZ output or SP1
BootInfo. All 256 digest bits are retained; there is no SNARK-field mask.

`benchmark.py` writes `*-proof-config.json` with independently expected output,
ELF/input hashes, terminal PC and explicit v3 service policy. Those files are
inputs for the existing combined producer and fresh receiver, not proof receipts.
On an already qualified GPU host, use its established library, resource budgets,
format selectors and resident-service configuration. The one-shot interface is:

```sh
rv64-word16-ethereum-gpu-combined produce-and-recurse-candidate \
  CASE-proof-config.json - PROOF_DIRECTORY 0 GPU_RESOURCE_JSON
rv64-word16-ethereum-gkr verify-recursion-candidate \
  CASE-proof-config.json PROOF_DIRECTORY FIXED_SETUP_BYTES
```

Run the receiver independently with the same explicit security/profile policy.
The current native target is conjectured 128-bit under the base branch's documented
assumptions, not a whole-protocol security certificate. No new cryptographic
profile or constraint is introduced here. GPU time, VRAM fit and recursive proof
acceptance for OP workloads must be measured on physical hardware.

`resident.py` packages only cases with matching native, production-RV64 and
independent-oracle receipts. Pass an existing qualified GPU manifest as the
template; it supplies all resource limits, recursion and security settings.
The package has relative asset paths and can be copied to the GPU machine.
Task ordinals in its manifest are scheduling identifiers, not L2 block numbers.

```sh
python3 opstack/resident.py --benchmark /tmp/kona-bench \
  --template /path/to/qualified-resident-manifest.json \
  --cases range-4 --workers 2 --devices 1 --output /tmp/kona-resident
# On the qualified GPU host, with its established producer environment:
cd /tmp/kona-resident
/absolute/path/to/rv64-word16-ethereum-gpu-combined combined-batch manifest.json proofs
```

The manifest's segment counts come from independently checked instruction counts
at the selected batch geometry. The producer still checks actual coverage and
byte admission. An input-ready package does not establish VRAM fit or acceptance.
Run the fresh receiver separately on each complete proof; preserve the exact
producer format selectors and disable receiver setup caches as the GPU harness
requires. The same manifest is compatible with the existing `combined-serve`
spool protocol, without an OP-specific scheduling implementation.

Full producer capture can be measured without a GPU. `capture.py` compares serial
and checkpoint/replay schedules at fixed geometry, rejects prefixes and requires
identical captured-value digests. It records per-child Linux peak RSS and process
wall time, including startup and diagnostic digest construction. It does not
produce or accept a proof.

```sh
python3 -m ziglang build rv64-capture-bench -Doptimize=ReleaseFast
python3 opstack/capture.py --request /tmp/kona-bench/26207960-proof-config.json \
  --execution /tmp/kona-bench/26207960-rv64.json \
  --runner ./zig-out/bin/rv64-capture-bench \
  --resources /path/to/bounded-capture-resources.json \
  --batch-steps 262143 --workers 0 1 2 --artifacts /tmp/kona-capture
```

## Validation

```sh
cargo +stable test --manifest-path opstack/kona/Cargo.toml --locked --features host --tests
PROPTEST_CASES=16 cargo +stable test \
  --manifest-path opstack/kona/vendor/kona-mpt/Cargo.toml --locked --lib \
  -- --skip test_online_
python3 -m unittest discover -s opstack/tests
python3 opstack/reject.py --request /tmp/kona-bench/26207960-proof-config.json \
  --execution /tmp/kona-bench/26207960-rv64.json \
  --fixture /tmp/kona-fixtures/block-26207960/fixture.json \
  --host /tmp/kona-frontier/host --runner /tmp/kona-frontier/rv64-execution \
  --artifacts /tmp/kona-negative
```

The upstream property generators still exercise insert/delete against Alloy's
independent HashBuilder; the offline command bounds their run count explicitly.
Do not run `cargo fmt --all`: that traverses the shared upstream runtime crates.
Format only the two owned packages (`-p stwo-kona-execution -p
stwo-kona-rv64-guest`) and the lean entry package. Keep unrelated vendor/runtime
formatting out of the diff.

## Remaining validity and settlement work

Execution of supplied payload attributes does not establish L1 availability,
valid sequencing, deposits or correct derivation. A verified Kona L1 derivation
and blob/KZG guest must bind exactly the same payload commitment. Then qualify
the execution/derivation bind in recursion, anchored L1 headers, reorg handling
and a running accumulator. SP1's runtime is not needed for those jobs, but their
constraints and independent acceptance are still required.

A production replacement also needs modern OP Mainnet/Base fixtures and broad
op-reth differential coverage, physical OP GPU measurements, bounded resident
job scheduling, final STARK compression and a direct on-chain STARK verifier.
There is deliberately no success flag or dummy verifier standing in for these
missing pieces. See the dated report under `vectors/reports/rv64-opstack-20261106`.
