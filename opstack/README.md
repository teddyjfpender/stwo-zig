# Kona on the RV64 proving stack

This is a runnable OP execution guest, not a completed OP validity prover. It
executes historical OP Mainnet and OP Sepolia blocks with pinned Kona, checks every resulting block
hash against an independent upstream fixture, and emits requests for the existing
native/recursive GPU pipeline. It uses no SP1 SDK or SNARK wrapper.

The current CPU-first [delivery gates](COMPLETION.md) distinguish execution,
anchored transition proofs, recursive closure and complete settlement. Historical
replay measurements do not close those later gates.

## Build and measure

Requirements: Rust `nightly-2026-08-08` with `rust-src`, Zig 0.15.2, Python 3.12+.
The optional independent execution oracle is pinned to Unicorn 2.1.4. RocksDB is
used only to import the upstream host fixtures, never in the guest.

```sh
rustup toolchain install nightly-2026-08-08 --profile minimal --component rust-src
python3 -m pip install -r opstack/requirements-host.txt
python3 opstack/build.py --variant sha --artifacts /workspace/kona-sha
python3 opstack/mainnet.py --output /workspace/kona-mainnet \
  --cache /workspace/kona-archive-cache --host /workspace/kona-sha/host
python3 opstack/benchmark.py --fixtures /workspace/kona-mainnet \
  --artifacts /workspace/kona-mainnet-bench --host /workspace/kona-sha/host \
  --guest /workspace/kona-sha/guest.elf --runner /workspace/kona-sha/rv64-execution \
  --profile ethereum_services_v3 --oracle
python3 -m ziglang build rv64-word16-ethereum-native -Doptimize=ReleaseFast -j1
python3 opstack/cpu.py \
  --request /workspace/kona-mainnet-bench/120794432-proof-config.json \
  --execution /workspace/kona-mainnet-bench/120794432-rv64.json \
  --runner zig-out/bin/rv64-word16-ethereum-native \
  --artifacts /workspace/kona-mainnet-cpu
```

The tested user-transaction block uses a larger batch, four proof workers and a
separately bounded single setup worker:

```sh
python3 opstack/cpu.py \
  --request /workspace/kona-mainnet-bench/121057303-proof-config.json \
  --execution /workspace/kona-mainnet-bench/121057303-rv64.json \
  --runner zig-out/bin/rv64-word16-ethereum-native \
  --artifacts /workspace/kona-user-block-cpu \
  --resources opstack/presets/cpu-4workers.json \
  --batch-steps 1048575 --workers 4 --setup-workers 1
```

The preset admits 4 GiB of retained frontend input, 1 GiB fixed setup and 8 GiB
of disk parking. These are component admissions, not a 4 GiB process-memory cap.
The verified two-lane preset uses `opstack/presets/cpu-8workers-2lanes.json`
with `--workers 8 --setup-workers 2`. The larger 2,097,151-step geometry on
block 121057303 uses `opstack/presets/cpu-8workers-single-lane.json` with
`--batch-steps 2097151 --workers 8 --setup-workers 2`. See the
[mainnet checkpoint](../vectors/reports/rv64-opstack-cpu-20261107/README.md).

Batch geometry comes from the request unless `--batch-steps` overrides it. The
benchmark-generated request uses 4,194,303; use the measured 1,048,575-step setting
above on a memory-constrained CPU host. Preserve the same geometry in comparisons.
The producer harness also accepts `--gkr-storage streamed-dense` and
`--gkr-storage materialized-checkpointed` for controlled storage experiments.
These modes preserve the transcript and have different memory admissions.
`--receiver-setup identity-only` optionally derives exact source coefficients
without committing an unused historical source Merkle tree; its candidate FIXED
authority is still independently reconstructed. The default remains `committed`.

The direct native `plan-candidate` command normally keeps a geometry census
and releases each completed witness shard. It still derives the chronological
RAM ledger and exact initial and terminal boundaries. The plan is a
producer-side trace-size diagnostic. Packet-directory plans, canonical rung
selection, and explicit capture digests use the retained capture path.

To use scratch-backed capture for direct native candidate production, add the
following field to the resource JSON on Linux or macOS.

```json
"capture_options": {
  "max_inflight_packets": 1,
  "spill": { "directory": "/workspace/kona-capture-scratch", "bytes": 8589934592 }
}
```

The byte cap covers live capture mappings, separate from the MAIN parking cap.
The runner reserves disk space before mapping and unlinks each scratch file.
Scratch backing can cost more time and is intended for workloads whose
retained witness would exhaust RAM. The receiver independently checks the
published candidate bundle.

Use the batch harness for bounded process-local setup reuse. The repeated
benchmark for block 120794432 uses
`opstack/presets/cpu-8workers-resident-small.json` and
`--cases 120794432 --workers 8 --setup-workers 2 --receiver-setup resident`.

```sh
python3 opstack/cpu_batch.py --benchmark /workspace/kona-mainnet-bench \
  --runner zig-out/bin/rv64-word16-ethereum-native \
  --resources opstack/presets/cpu-4workers.json \
  --cases 120794432 121057303 --repeat 2 --batch-steps 1048575 \
  --artifacts /workspace/kona-mainnet-cpu-resident
```

Every result must pass a verifier process separate from the producer before the
harness records `proof_verified=true`. By default each bundle starts a fresh
receiver. Add `--receiver-setup resident --receiver-key-bytes 3221225472` to
receive the entire batch in one independently started process. It derives source
keys and FIXED roots itself and retains only immutable setup under the separate
key budget. Each bundle still undergoes file, statement, proof and endpoint
checks. Corruption trials also run through that process mode.

Native `batch-candidate MANIFEST OUT` produces an index that records production
only. Native `verify-batch-candidate MANIFEST` accepts the bounded
`rv64-cpu-receiver-inputs/v1` manifest generated by the harness and writes one
JSON report per request in order. Require successful process exit and every
expected report. The key budget and FIXED-setup admission are separate component
budgets. The receiver refuses a persisted setup directory and derives authority
independently of the producer. Failed runs retain receipts and cannot pass as prefixes.

For the native CLI, `STWO_ZIG_RV64_RECEIVER_SETUP_THREADS=4` allows up to four
concurrent source-key builders for identity-only or resident reception. The
Python harnesses expose the same setting as `--receiver-setup-workers 4`. The
default is one and the accepted range is 1–8. The receiver charges each setup
helper's stack to the request budget until the helpers join. The request's
`workers` value separately controls the pool for checking physical proofs.
Compare `load_and_setup_ns` and `verify_ns` on a cold request and on subsequent
resident requests. Resident reuse removes the cold source-key construction,
while every request still checks its own proof bundle.

`software`, `keccak`, `services` and `sponge` retain the upstream EVM/MPT source.
`lean` additionally uses the existing optimized Revm interpreter/bytecode crates
and the local capped-length MPT change. `frontier` is that guest with full LTO.
`memory` additionally enables the existing constrained bulk-memory services.
`sha` uses the admitted SHA-256 compression service for statement hashing;
`memory-sha` combines both. `arithmetic` adds the admitted EVM ADDMOD/MULMOD
service to SHA; `full` combines those with bulk memory. `bn254` additionally
selects the experimental BN254 Montgomery adapter. The reference host retains
software SHA-256 and the upstream Ark field implementation.

`precompiles` installs the admitted SHA/modexp/BN254-G1 provider. `pairing` adds
bounded exact-byte pairing and prepared-G2 reuse; `optimized` also enables the
admitted JUMPDEST scanner and aligned immutable bytecode storage. `canonical`
uses the optional guest-only canonical Fq/Fp2 adapter. `canonical-glv` additionally
uses joint-window GLV for G1 multiplication. `canonical-glv-hinted` adds the
optional checked pairing residue path. All are explicit experimental choices;
see [precompile boundaries](PRECOMPILES.md) for validation and software fallbacks.

The mainnet corpus contains six nonadjacent Ecotone-era blocks (120794432,
121003241, 121049889, 121057303, 121065789, 121135704), including a deposit-only
block and blocks with user transactions. Its source and preimage archives are
pinned in `mainnet-fixtures.json`. Import requires every Keccak preimage hash,
canonical headers, parent linkage, the actual Kona chain 10 registry, and native
execution reproducing the complete expected block hash. Downloaded Rust source
is parsed as data, never executed. This is historical mainnet coverage, not a
current-head or all-forks claim. Outputs publish only after all selected replays
pass. The cache can be populated offline with the same hash-pinned source bytes.

`benchmark.py` defaults to this mainnet corpus and isolated blocks. For the old
four-block regression corpus use `prepare_fixtures.py` and explicitly select
`benchmark.py --network sepolia`; adjacent range benchmarks remain available.

`cpu.py` pins the current native conjectured-128 profile, uses all v3 services,
measures proof production and fresh reception separately,
and requires rejection after corrupting actual persisted CPU proof bytes. It
uses fresh subprocesses, one lane, explicit worker
counts and resource admissions. Linux `wait4` reports peak RSS, which is measured
rather than an enforced process cap. macOS reports RSS in bytes; Linux reports
KiB, converted to bytes in new receipts. The CPU harnesses accept
`--receiver-bytes` (default 6 GiB, maximum 64 GiB) for an explicit requested-live
receiver admission, separate from fixed setup and measured RSS. Changing this
operational budget changes no proof or security parameter. Older receipts keep
their original measurements and platform context. The source-derived plan reports exact
FIXED/MAIN/INTERACTION cells and MAIN+INTERACTION payload bits; it excludes PCS,
composition and recursion, and is never called a proof or proof-size estimate.
No compilation enters the proof wall time. A prefix cannot pass this harness.
Production always performs its native source, geometry and resource admissions.
Add `--plan-first` when a separate source-cost census is needed; it replays
execution/capture before production and is recorded as an extra stage. The
default avoids that duplicate work. This does not bypass native admission.
Producer setup defaults to process-local identity-only sharing (`--setup ephemeral`),
with no setup files loaded or persisted. `--setup uncached` supplies the older
control. The receiver has a separate clean environment and always rebuilds its
own source authority; it never inherits producer cache selections. Use
`--resources FILE` for explicit admission budgets and `--batch-steps` for geometry.
Proof workers (`--workers`) and setup-build workers (`--setup-workers`, default 1)
are independent, so FFT parallelism need not multiply setup memory. A supplied
resource file owns its lane schedule; that schedule and the native pool size are
recorded separately. Limits,
failures and Linux peak RSS are retained beside each stage. A larger
admission budget does not reserve physical memory. A per-stage heartbeat records
when the supervisor last observed its child; it is progress metadata, never proof
authority, and is removed when the stage is reaped.

The native-only executable uses the same statement, source admission, service
roster and persisted proof receiver as the GPU-linked driver. Its CPU product
has no recursion-module dependency. The existing linked driver and its recursion
policy checks are preserved. Recursive modes are unavailable in the native-only
product.
All choices are explicit. A lower guest instruction count is not a measured GPU
speedup: service calls, permutations and bytes remain proving work.

The native reference uses the upstream Kona MPT. Each measured RV64 case must
match its output and the fixture's block hashes. The optional independent oracle
checks completion at exactly N instructions (N-1 then 1), all 32 registers, PC,
43 output bytes and service counters. The production RV64 diagnostic is reused;
there is no OP-specific implementation of the VM or crypto executor.

## Full block CUDA benchmark

Run the build, fixture import and execution benchmark above with
`--profile ethereum_services_v3 --oracle`. On a Linux CUDA host with a matching
[resident native CUDA runtime](../design/riscv-proving-stack/rv64-gpu-handoff-20261104.md),
build the producer and independent CPU receiver from the same checkout:

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig \
  build-rv64-ethereum-gpu -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu \
  -p "$PWD/zig-out" -j1
zig build rv64-word16-ethereum-native -Doptimize=ReleaseFast -j1
python3 opstack/gpu.py --block 121057303 \
  --benchmark /workspace/kona-mainnet-bench \
  --receiver zig-out/bin/rv64-word16-ethereum-native \
  --driver zig-out/bin/rv64-word16-ethereum-gpu \
  --runtime "$RV64_NATIVE_LIBRARY" --runtime-sha256 "$RV64_NATIVE_LIBRARY_SHA256" \
  --resources opstack/presets/cuda-resident-8workers.json \
  --batch-steps 1048575 --devices 0 --artifacts /workspace/op-cuda-121057303
```

Set the runtime path and SHA-256 from the matching native image's build
receipt. The [image builder](../scripts/rv64_cuda_resident_image_build.py)
links the generated CUDA kernels; the driver loads that image at runtime. The run keeps the exact
input, program and tool hashes, source-derived CPU scope count, measured CUDA
launch and event evidence, producer wall and RSS, sampled whole-device memory,
and separate CPU receiver result. It reports success only after the receiver
checks the complete block and exact pinned output with CUDA disabled. GPU
event spans can overlap, and sampled device memory includes other processes.
This path measures native proofs, without recursion or L1 derivation.

Use `--repeat 2` to measure cold and warm requests in one resident process.
The warm trial must reproduce the independently accepted cold bundle byte for
byte. Reported producer throughput includes process startup and teardown.
The independent receiver's wall time is recorded separately.

For block **121065789**, use a separate `canonical-glv-hinted` build and
`benchmark.py --pairing-hints --blocks 121065789 --oracle --profile
ethereum_services_v3` to reproduce the 425,529,933-instruction input. Start
with `gpu.py --prepare-only --block 121065789 --devices 0 1 --batch-steps
4194303`; this uses the same receiver, benchmark, resource and artifact
arguments, with no driver or runtime needed. The existing census at this
geometry counted **102 CPU scopes** and **122.5 GiB** of raw padded MAIN at
four bytes per field cell. The scope table allows 64 CPU scopes per device.
Passing the scope count check on two devices does not establish device memory
fit: compact replay, device representations, live buffers and allocator
overhead are accounted for by the runtime. Set explicit budgets for the
available host and device memory, using a fresh artifact directory for the
attempt. If using capture spill, add it after the no-spill census and give it
a separate, adequately sized filesystem; the previous 40 GiB backing cap
was exhausted. This preset is a starting point for the smaller block, with
no heavy-block memory or latency claim.

## Validation and dependency ownership

```sh
python3 opstack/validate.py --fast
python3 opstack/validate.py  # offline Rust/field/property checks too
```

Run the builds once to populate pinned dependencies before the offline gate.
The fast gate checks Python formatting, rejection tests and unchanged vendored
source identities. Imported Rust files retain upstream formatting; only owned
packages and new test/adapter files are formatted. Dependency deltas are listed
in [the vendor map](kona/vendor/README.md).

Builds require fresh artifact directories and explicitly record COPY/UCOPY/SET/CMP
thresholds. Compiler-input inventories include shared runtime patches and Zig
sources; a changed or newly added input during a build prevents publication of
a successful build receipt. The execution runner reuses Cargo's local target
cache, then copies the exact binary to the fresh artifact directory. Ambient
`STWO_ADMITTED_*` compiler settings are cleared. `--bulk-min`
selects a common value of 8..1048576 or `off`; defaults remain 16/16/16/8. Values
below 8 are rejected before the existing wrapper can peel an unaligned head.

The [maintained mainnet report](../vectors/reports/rv64-opstack-mainnet-20261106/README.md) separates guest execution, exact source-cell cost,
CPU proof production, fresh reception and negative controls. A diagnostic
execution receipt's `proof_supported: false` describes that execution command;
only the separate CPU receipt establishes physical STARK proof verification.

## Architecture

| Location | Responsibility |
|---|---|
| `kona/src/witness.rs` | Borrowed sorted preimage table; canonical bounds/offsets; authenticate each used Keccak preimage before access; a validation bitmap avoids repeated hashing. |
| `kona/src/metadata.rs` | Complete binary payload attributes, RLP parent header, bounded range and canonical rollup configuration; public payload commitment. |
| `kona/src/execution.rs` | One pinned Kona stateless builder per range; retains the updated trie between adjacent blocks. |
| `kona/guest` | RV64IM runtime, existing allocator/atomics/memory ABI, explicit constrained crypto features, OP output schema. |
| `kona/lean` | Separate dependency/optimization policy; no change to the reference host. |
| `kona/vendor/kona-mpt` | Pinned source with capped RLP reference sizing, source hashes and byte-level differential tests. |
| `mainnet.py`, `kona/src/host/mainnet.rs` | Authenticated historical mainnet import and actual registry configuration. |
| `cpu.py` | Cold CPU production, fresh reception, tamper rejection and separate stage receipts. |
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
cargo +stable test --manifest-path opstack/kona/Cargo.toml --locked --features host,blob-derivation
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

`verify_calldata_transition` authenticates L1 ancestry and safe L2 history,
derives the next payload in Kona, and binds execution to the expected output
root. With `blob-derivation`, `verify_blob_transition` also accepts up to 256
sidecars. It resolves blob hashes from the authenticated L1 transaction body,
checks canonical field encodings and verifies Ethereum KZG against the blob
challenge. The blob test vector is generated with c-kzg 2.1.8. A positive
mainnet transition still needs the complete safe history, L1 derivation data
and output-root witness. The execution guest currently proves supplied payload
attributes. The derivation and execution binding still needs RV64 proof and
recursive admission.

A production replacement also needs modern OP Mainnet/Base fixtures and broad
op-reth differential coverage, physical OP GPU measurements, bounded resident
job scheduling, final STARK compression and a direct on-chain STARK verifier.
There is deliberately no success flag or dummy verifier standing in for these
missing pieces. See the dated report under `vectors/reports/rv64-opstack-20261106`.
