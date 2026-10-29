# EVM block proving with Keth and Stwo Zig

This owner-operated experiment feeds Kakarot Labs' **Keth** Cairo execution
programs into the existing Stwo Zig CPU/Metal products. The measured block
bundle uses a narrow adapter for the pinned Keth execution witness.
Released AIRs, proof protocols and verifier pins are unchanged.

## Verified full-block measurements, 2026-10-29

Both CPU and Metal completed all **45 proofs** of block 22,615,247, including
all transactions, teardown, all sixteen trie branches and the consistency
program. All retained proofs passed a second independent official Rust
verification. The CPU and Metal proofs are byte-identical for every segment.
Receipts and manifests are in [the retained evidence](evidence/2026-10-29-m5-max).

Host: Apple M5 Max, 18 CPU cores, 64 GiB unified memory. Compact input and
canonical security throughout. Each row is
**one complete block sample**; repeated trials and additional workloads remain
necessary for a throughput/capacity conclusion.

| Backend | Workers | Transactions/chunk | Converter | End to end | Proving | Peak physical footprint |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| CPU | 4 | 1 | Python | 438.5 s | 212.6 s | 16.53 GiB |
| Metal | 4 | 1 | Python | 361.6 s | 136.3 s | 13.65 GiB |
| CPU | 8 | 1 | Rust | 301.2 s | 138.0 s | 16.53 GiB |
| CPU | 8 | 2 | Rust | 232.7 s | 112.3 s | 16.53 GiB |
| CPU | 8 | 4 | Rust | 203.9 s | 102.2 s | 18.83 GiB |
| Metal | 8 | 4 | Rust | 158.4 s | 57.1 s | 15.65 GiB |

Four-transaction chunks use 26 proofs. The later Metal row inherits the archive
populated by the earlier run; each run retains the observed cache hits and
compilations. These rows compare complete configurations. Three further complete
runs of the last configuration took **156.44, 158.33 and 158.17 s**, median
**158.17 s**, sample standard deviation **1.05 s**. Their median proving time
was **56.22 s**. All 78 proofs from those three runs passed independent retained
proof re-verification. See [the campaign evidence](evidence/2026-10-29-m5-max/metal-w8-chunk4-repeats/campaign.json).

The CPU run spent 104.1 s tracing and 76.6 s converting witnesses. Its 106.4
million Cairo opcode transitions include 59.6 million for transaction bodies,
38.2 million for trie diffs and 8.2 million for teardown. Transaction-body and
trie-diff proving each contributed about 45% of proving time. Peak memory was
in teardown. The 8 GiB limit used in the original experiment is insufficient
for this complete workload, even with one transaction per chunk.

Proofs total 362,768,680 bytes of JSON and 87,474,716 bytes compressed. These
are 45 independently verified proofs with a consistency proof. The full local
bundles, witnesses, logs and per-stage profiles are under
`block-data/keth-integration-20261029/`. One real EVM init proof is also retained
in the evidence directory; full proof hashes are in the manifests.

Metal's first init process took 38.3 s, including 40 pipeline compilations;
subsequent measured body processes hit the disk archive and took about
1.2–2.5 s. Both startup and later process measurements are retained. GPU RSS
understates product memory here; the table uses Darwin physical footprint,
including Metal allocations, measured separately from RSS.

The native converter below produced byte-identical compact inputs for all
45 verified segments, with matching program, instruction and execution counts.
Its conversion processes totalled 15.6 s with 1.35 GiB peak RSS, versus 76.6 s
and 5.63 GiB for the Python reference. This comparison uses retained inputs;
fresh full-block runs measure its effect on the complete pipeline.

The monolithic `main` execution also traced successfully: 64,655,334 native
steps. Its 632,839,371-byte PIE exceeds the existing VM adapter's 256 MiB
admission limit. The direct witness route produced a valid 1,815,835,512-byte
compact input without changing that limit. Inspection reports 31.68 GiB of
known base/interaction trace storage and eight unresolved feed components;
this storage total is explicitly **not** a peak-memory estimate.

CPU and Metal monolithic proving were both attempted with a 48 GiB product
physical-footprint watchdog. Both crossed the limit before proof publication
and were terminated. CPU compact-polynomial storage also crossed it. These are
retained failed capacity attempts, not completed proofs or measurements of the
eventual peak. The successful segmented runs remain the measured configuration
for this 64 GiB host. `main_witness.py` reproduces direct tracing/conversion and
inspection; `bounded_prove.py` records canonical proving attempts with the
Darwin footprint watchdog. The watchdog bounds neither aggregate host RAM nor
simultaneous parent/child memory.

```sh
cargo +1.96.0 build --release --locked \
  --manifest-path autoresearch/experiments/evm_keth/legacy_input_rs/Cargo.toml
python3 -m unittest autoresearch.tests.test_keth_stwo_bridge \
  autoresearch.tests.test_keth_fast_converter autoresearch.tests.test_keth_op_blobs
python3 autoresearch/experiments/evm_keth/qualify_converter.py \
  --bundle block-data/keth-integration-20261029/ethereum-cpu-w4-chunk1 \
  --keth-checkout ../keth-pinned \
  --converter autoresearch/experiments/evm_keth/legacy_input_rs/target/release/keth-legacy-input \
  --out /tmp/keth-converter-qualification
```

Select it in `bundle_benchmark.py` with `--converter` and the same binary path.
The reference Python converter remains the default. Both check the complete
compiled public program image and the instruction cache before publishing.

`campaign.py` accepts the same product, fixture, oracle, converter, worker and
chunk arguments, plus `--trials`. Each trial runs a complete fresh bundle,
independently re-verifies every retained proof again, and contributes a complete
block sample. The campaign reports medians, ranges and sample standard deviations;
failed trials remain failed.

The first real workload is Ethereum mainnet block **22,615,247**, hash
`0x0497f69549701d578c67a43951f9e4fcb92b1691b9f6bbdfa63a17bc41d3971e`:
26 transactions, 16 withdrawals, and 1,331,413 gas. Its witness is committed in
[the pinned Keth source](https://github.com/kkrt-labs/keth/blob/e90c0a51699182f140e51c94d09ff9045c194769/test_data/22615247.json).
An independent Ethereum RPC snapshot confirms the header hash, state root,
transaction count and gas usage. The header was also checked with Ethereum
RLP encoding and Keccak, including its parent link.

## Remaining gap and completion criteria

The current result is a verified Keth workload for one Ethereum block, plus
independently proved OP fee and call-deposit kernels. A complete OP block
validity proof and an operational settlement path remain unfinished. The work
below is required before claiming either; kernel timings do not predict full
OP block cost.

| Priority | Remaining work | Evidence required to close the gap |
| --- | --- | --- |
| 1 | Finish execution soundness and state authentication. Persistent read keys, initial storage-root metadata and initial created-account markers are constrained; transaction-local dictionary/default values still need audit. | Adversarial witness/hint tests preserving bytecode; constrained account/storage membership against the initial MPT root; computed final MPT root; exact public chain, block, parent and state-root binding. Host root checks remain a reference oracle. |
| 2 | Execute all OP sequencer transactions in Cairo. The fee kernel proves fees with supplied parameters; the deposit kernel covers one call deposit. | All 34 sequencer transactions in the retained OP block match op-geth gas, status, logs and intermediate state; fee parameters read from authenticated state; exact sender refunds and base/L1/operator vault credits. |
| 3 | Complete OP block and fork behavior. | Deposit creation and failure cases, system calls, OP precompiles and fork-specific gas/input limits; complete typed receipts, transaction/receipt roots, withdrawals/message-passer root, requests and DA-footprint checks; a fully verified block bundle with complete ordered linkage. |
| 4 | Prove L1-to-L2 derivation and authorization. The recovered Base batch has been decoded and matched to observed blocks. | Authenticated L1 inputs and blob data; dynamic batcher/SystemConfig authorization; channel/span acceptance, L1 origin and sequence rules, deposit inclusion/source authorization; derivation outputs bound to proved L2 execution. |
| 5 | Integrate recursive verification and settlement. Keth's current aggregator checks commitment consistency. | A recursive verifier that actually verifies child proofs, compression as required by the intended settlement verifier, an explicit public-input contract, and positive/negative settlement-verifier tests. |
| 6 | Establish representative cost and capacity. Current complete Ethereum measurements cover one Prague block; complete OP proving is not measured. | Repeated complete Ethereum and OP/Base blocks across transaction types, gas/state/code sizes and forks; witness acquisition, tracing, conversion, proving, verification, memory and disk costs; worker/chunk/cache comparisons and sustained throughput. Monolithic attempts exceeded a 48 GiB footprint guard before completion. |
| 7 | Restore repository release gates and independent reproduction. | Resolve provenance and source-conformance findings without weakening gates, obtain required platform CI results, and reproduce retained canonical proof/evidence checks from the documented source pins. |

The immediate sequence is execution/default-value audit, sequencer execution
against the 70 native checkpoints, state-root/public-statement binding, then a
complete OP block campaign. Derivation and settlement follow with their own
verified interfaces. The open CI failures remain release gates throughout.

## Integration

The current branch also merges upstream PR304 head `22af4fdd7`. A real
interrupted Metal bundle resumed from one independently reverified init proof,
rejected altered retained bytes, and completed all 26 proofs. Every proof is
byte-identical to the earlier CPU and Metal runs. This is a resume correctness
qualification, with interrupted timing explicitly labeled; evidence is in
[`pr304-merge-qualification/`](evidence/2026-10-29-m5-max/pr304-merge-qualification).

1. Keth's unchanged native hint processor executes `init`, transaction `body`
   chunks, `teardown`, all 16 `mpt_diff` branches, and `aggregator`.
2. `legacy_input.py` admits the pinned legacy witness schema, checks every
   compiled program cell against public memory and every cached instruction
   against memory, then translates three opcode names and eight builtin names.
   Instruction-cache length becomes `pc_count`; witness values are preserved.
3. The existing Zig Cairo frontend proves and self-verifies each segment at
   canonical security. The unchanged official Rust verifier independently
   accepts the exact bytes of every proof.
4. Every verified public output must match Keth's execution. The consistency
   proof must publish the exact ordered concatenation of all verified child
   outputs and their program hashes, with complete transaction and trie coverage.

Keth pins Stwo-Cairo `92232543…`; this repository's Cairo frontend pins
`82f21252…` (1.2.2). Their proof formats are not interchangeable. This bridge
translates execution-witness schema only, then generates a new proof with the
existing Zig product and official verifier. JSON and the existing compact-v1
transport are supported. The recorded bundle combines JSON transaction inputs
with compact state/trie inputs; each trial records its transport. Source identities are in [pins.json](pins.json).

The independent PIE route is retained in `block_benchmark.py`: export a genuine
Keth PIE, replay it through the pinned official simple bootloader, then prove
and verify. It hashes the large EVM program inside Cairo; the real init segment
expands from 273,352 native steps to 3,041,759 proved steps. Direct witness import
avoids that cost. Neither path changes released AIRs, verifier pins, or security.

The `aggregator` is a **commitment consistency checker**, not a recursive child
proof verifier. A bundle qualifies only when every child independently verifies
and its exact output appears in the consistency proof. `verify_bundle.py`
rechecks the retained compressed proofs against the trusted benchmark manifest.

A complete proof of this workload benchmarks Keth's program and witness. It
is not by itself proof of Ethereum consensus, an OP Stack derivation pipeline,
or compatibility with an Ethereum settlement verifier. The bridge keeps
those application-level claims false.

## Measured complete block bundle

All **45 proofs** for block 22,615,247 qualified on an Intel Xeon Platinum
8573C host, with four CPU workers and an 8 GiB container memory limit. Every
retained proof passed a second independent official Rust verification, including
exact public-output and compiled-program identity checks. The bundle covers
**106,374,029 Cairo opcode transitions**.

| Stage | Proofs | Product time (s) | Proving time (s) | Official verification (s) |
| --- | ---: | ---: | ---: | ---: |
| Initialization | 1 | 12.087 | 11.563 | 0.317 |
| Transactions | 26 | 769.760 | 702.067 | 10.072 |
| Teardown | 1 | 531.755 | 530.584 | 0.291 |
| Trie branches | 16 | 2,567.994 | 2,560.353 | 1.288 |
| Commitment consistency | 1 | 14.529 | 14.428 | 0.050 |
| **Total** | **45** | **3,896.125** | **3,818.994** | **12.018** |

These are sums of unique successful stage measurements, with one trial per
stage. Compilation, failed attempts, and repeated verification during resume
are excluded from the table. The run spans six driver sessions and two adopted
standalone capacity retries; **there is no uninterrupted end-to-end latency or
throughput sample**. Native tracing and witness conversion additionally total
598.922 s and 729.195 s. Multiple producer builds are identified per stage in
the manifest; they differ in allocator capacity settings.

Peak reported product RSS was **5,247,311,872 bytes (4.89 GiB)**; peak temporary
file backing was **14,217,551,872 bytes (13.24 GiB)**. RSS comes from Linux
`wait4`, including pre-exec/inherited high-water effects; file cache makes it
different from total physical footprint. Transaction stages used ordinary RAM;
teardown, trie, and consistency stages used the opt-in file-backed allocator.
The retained compressed proof JSON totals **87,474,716 bytes**.

Machine-readable evidence: [manifest](evidence/ethereum-22615247-bundle.json),
[summary](evidence/ethereum-22615247-summary.json),
[independent reverification](evidence/ethereum-22615247-reverified.json), and
[host](evidence/benchmark-host.json). The proof archive is published with the
benchmark result; the repository also retains an independently verified
[real transaction proof](evidence/ethereum22615247_tx0.proof.bz2).
The complete archive's size, SHA-256 and CRC validation are recorded in
[the archive receipt](evidence/ethereum-22615247-archive.json).

## Run the real-block benchmark

Install the upstream Keth environment with Python 3.10 and its pinned Rust
nightly, then compile its programs. Set `CAIRO_PATH` as in Keth's `.env.example`.
Builds are excluded from runtime measurements.

```sh
# In the clean, pinned Keth checkout:
RUSTUP_TOOLCHAIN=nightly-2025-04-06 CARGO_BUILD_JOBS=2 uv sync --frozen
# Compile serially on a machine with 8 GiB RAM.
export PYTHONPATH=cairo
export CAIRO_PATH=cairo:python/cairo-ec/src:python/cairo-addons/src:python/cairo-core/src:python/mpt/src:.venv/lib/python3.10/site-packages
.venv/bin/python - <<'PYCOMPILE'
from pathlib import Path
from scripts.compile_cairo import compile_cairo, save_program_hashes
Path('build').mkdir(exist_ok=True)
programs = {'main': 'main', 'init': 'init_main', 'body': 'body_main',
            'teardown': 'teardown_main', 'mpt_diff': 'mpt_diff_main',
            'aggregator': 'aggregator_main'}
hashes = {}
for role, name in programs.items():
    output, value = compile_cairo(Path(f'cairo/ethereum/prague/keth/{name}.cairo'),
                                 proof_mode=True, output_path=Path(f'build/{role}_compiled.json'))
    hashes[output] = value
save_program_hashes(hashes, 'build')
PYCOMPILE
```

Build the existing Stwo Zig CPU product and official Rust verifier. Current
locked Cairo 2.20 adapter dependencies require a newer Rust compiler than the
older documented oracle nightly; `nightly-2026-05-15` built the unchanged
adapter and verifier successfully during the smoke qualification.

The capacity command below is for Linux. On macOS, omit the three file-backed
allocator variables and `--rss-limit-bytes`, and select
`--max-address-space-gib 0`; Darwin physical footprint is recorded separately.

```sh
RUSTUP_TOOLCHAIN=nightly-2026-05-15 zig build stwo-cairo-cpu -Doptimize=ReleaseFast -j1
cargo +nightly-2026-05-15 build --release --locked \
  --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml

STWO_CAIRO_FILE_BACKED_ALLOCATOR=1 \
STWO_CAIRO_FILE_BACKED_MIN_BYTES=16777216 \
STWO_CAIRO_FILE_BACKED_COOLING_BYTES=536870912 \
STWO_CAIRO_CPU_WIDE_LDE=0 STWO_CAIRO_OVERLAP_PREPROCESSED=0 \
STWO_CAIRO_INCREMENTAL_MULTIPLICITIES=1 STWO_CAIRO_COMPACT_POLYNOMIALS=1 \
python3 autoresearch/experiments/evm_keth/bundle_benchmark.py \
  --keth-checkout /path/to/keth \
  --fixture /path/to/keth/test_data/22615247.json \
  --product zig-out/bin/stwo-cairo-cpu \
  --oracle tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier \
  --workers 4 --chunk-size 1 --input-format compact \
  --max-address-space-gib 32 --rss-limit-bytes 8000000000 \
  --out /tmp/keth-ethereum-bundle

python3 autoresearch/experiments/evm_keth/verify_bundle.py \
  --bundle /tmp/keth-ethereum-bundle \
  --oracle tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier \
  --out /tmp/keth-bundle-reverification.json
```

This reproduces the proof workload using the capacity configuration. Large
allocations use temporary disk backing; the resident guard remains below the
container's 8 GiB hard memory limit. The measured teardown used 14.22 GB of
temporary backing, all released after proving. Virtual-address capacity and
resident memory are separate limits. The allocator defaults to a 1 MiB backing
threshold and a 64 MiB cooling interval; the command selects 16 MiB and 512 MiB.
Canonical security is unchanged. Disk I/O is part of the measured proving time.

`--resume` rechecks every retained proof and exact public statement before
continuing a failed run. Partial prefixes never qualify as complete bundles.
An interrupted bundle is labeled separately from a fresh end-to-end sample.
`qualify_resume.py` proves a real init segment, deliberately interrupts the first
body stage, confirms that changed retained bytes reject, restores those bytes,
then resumes and independently re-verifies the complete bundle. It accepts the
same checkout, fixture, product, oracle and converter arguments, plus `--out`.
Its default virtual-address limit is disabled; choose an explicit Linux limit
when required. A session killed before recording its duration leaves total
elapsed time unknown, rather than fabricating a complete latency measurement.
Native exports and converted inputs are temporary; the evidence tree retains
proofs, public outputs and receipts. The recorded sample includes interrupted
sessions and separately verified capacity retries: sum unique accepted stage
times and do not interpret it as an uninterrupted end-to-end throughput sample.

The driver records native execution, witness conversion, complete product-process
and proving time, independent verification, source/input/binary hashes, public
statements, and peak process RSS. The canonical policy is 70 queries, 26
proof-of-work bits and log blowup 1. Compilation is excluded. All segments run
serially; the fresh bundle cache is retained between segments. Proofs are retained
as bzip2-compressed JSON and individually hashed. Inputs can be retained with
`--keep-inputs`; normally the large intermediates are removed after verification.

The address-space limit is a per-process guard, not a peak-memory estimate or
a bound on the sum of simultaneous parent/child memory. Failed stages remain
visible and never qualify. The original 8 GiB guard is insufficient for the
measured complete bundle. Larger transaction chunks and monolithic `main`
capacity require measurements at the selected limit. No unsuccessful run is
reported as a block proof.

`RLIMIT_AS` enforcement is supported on Linux. The default is 8 GiB on Linux
and disabled (`0`) on other platforms; Darwin rejects practical `RLIMIT_AS`
limits. Select a sufficient limit for the measured workload. Every new bundle
records whether the limit was enforced. CPU and Metal memory measurements
remain available when the virtual address-space guard is disabled.

## Supported chain scope

| Workload | Current scope |
| --- | --- |
| Ethereum Prague block witness | Keth's implemented execution path; first target above |
| Optimism and other OP Stack chains | Require deposit/system transaction, fees, fork and output-root compatibility; ordinary EVM compatibility alone is insufficient |
| OP Stack derivation | Requires a separate proved L1-to-L2 derivation path, cryptographically bound to execution |

`op_stack_journal.py` is a strict **host ABI codec**, not a proof verifier, for
the five-word OP Succinct range journal. Running Kona's Rust implementation
itself would be a separate RISC-V integration. No OP Stack chain is reported as
proved by this experiment without its own compatibility and verification evidence.

Real finalized RPC observations were retained for OP Mainnet block 158,839,441
(35 transactions; 13,920,542 gas) and Unichain block 62,529,693 (12 transactions;
799,080 gas). Both include type `0x7e`, absent from the pinned Keth decoder.
The [pinned OP chain configuration](https://github.com/ethereum-optimism/superchain-registry/blob/fcc7f4bf9fe577531f0e15eba52e3d8d6679f3e9/superchain/configs/mainnet/op.toml)
and the corresponding Unichain configuration activate Karst at these block
timestamps. OP Mainnet has a two-second block interval; Unichain has one second.
The assessment therefore needs chain-specific fork rules and block cadence.

The Ethereum fixture itself also includes a submission to Base's
[historical batch inbox](https://github.com/ethereum-optimism/superchain-registry/blob/5b055be4d294ce43814a44c8839d89b2436dc8aa/superchain/configs/mainnet/base.toml):
transaction index 15, hash
`0xde4edf4f7d27981d86b57420bd9b9f294f73b2ca5d2513a723bdddf407392341`.
It uses 21,000 gas and carries three blob versioned hashes with empty calldata.
Its one-transaction CPU proof took 3.47 s and 1,745,224 Cairo transitions.

The three archived blobs are retained with their metadata. Their KZG proofs and
recomputed commitments match the exact hashes in the signed L1 transaction.
OP decoding reconstructs one 372,931-byte Brotli channel with three span batches.
Their metadata declares **12 L2 blocks and 2,437 sequencer transactions**; L1
attribute and user deposit transactions are additional derivation work.
Transaction bodies, batch authorization, derivation acceptance and L2 execution
are not established by this metadata inspection. The recorded counts make the
L1-submission and L2-execution workloads explicit.

The pinned official OP `batch_decoder` subsequently accepted the complete
channel with no invalid frames or batches and reconstructed all **2,437 raw
transaction bodies**: 1,938 type-2 and 499 legacy transactions, including two
unprotected legacy transactions. Explicit chain IDs match Base (8453). The
timestamps map to historical Base blocks **31,028,358–31,028,369**. Compressed
reference inputs/outputs, rollup configuration, all transaction hashes and
source/binary hashes are retained in `base-l1-batch/official-codec-validation.json`
and adjacent artifacts. This validates the transaction codec, with the reference
decoder's sender-admission flag supplied from the RPC sender matching the
historical genesis batcher. Dynamic SystemConfig authorization, derivation
acceptance and L2 execution remain separate work.

The recovered sequencer transactions now match the full ordered transaction
lists of all twelve historical Base blocks. Two RPC endpoints agree on their
headers and transaction lists. `check_op_workload.py` independently reconstructs
each RLP/Keccak header, all transaction roots and all receipt roots, including
the twelve type-`0x7e` L1-info deposits and Canyon deposit receipt extensions.
It checks each deposit source hash, Isthmus L1-info encoding, span parent/origin
checks, L1-origin sequence transitions, and the observed Ethereum origin headers.
The blocks total **826,763,923 gas**, range **54,653,077–84,792,921 gas/block**,
and include **101 failed transactions**. This is workload characterization;
execution time cannot be inferred from a gas ratio to the smaller Ethereum
fixture. Dynamic batch authorization and consensus authentication remain false.

Compressed full blocks, parents, receipts and independent reads are retained in
`evidence/2026-10-29-m5-max/base-historical-blocks/` (about 2 MB). Reproduce these
offline checks with Keth's pinned Python environment:

```sh
../keth-pinned/.venv/bin/python autoresearch/experiments/evm_keth/check_op_workload.py \
  --channel autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-l1-batch/official-decoded-channel.json.gz \
  --blocks autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-historical-blocks \
  --config autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-l1-batch/official-rollup-config.json \
  --l1-headers autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-historical-blocks/l1-origins \
  --out /tmp/base-workload-check.json
../keth-pinned/.venv/bin/python -m unittest \
  autoresearch.tests.test_keth_op_workload autoresearch.tests.test_keth_state_proofs
```

`state_proofs.py` verifies secure MPT account/storage membership and
non-membership, account fields and code hashes against supplied roots. It has
real pre/post OP account evidence and tamper-rejection tests. These are host
checks and add no Cairo constraints. `collect_state_witness.py` uses an ordered
pre-state trace to collect candidate accesses, adds known system accesses, paces
requests and rechecks retained proofs before reuse. A collected candidate set
is sufficient only after independent offline execution succeeds.

`assemble_op_reference.py` emits inputs for `op_reference/main.go`, built using
the pinned official Optimism module and its unmodified op-geth dependency. The
runner compares computed state/receipt roots and post-Isthmus withdrawal storage
roots with the observed header. It emits separate false Cairo, derivation and
consensus claims. The builder audits the clean reference revision and uses
explicit tool pins outside its mise configuration:

```sh
python3 autoresearch/experiments/evm_keth/build_op_reference.py \
  --reference-checkout ../optimism-op-batch-reference \
  --out /tmp/op-reference-execution
```

Historical Base proofs/traces were unavailable on the tested public endpoints;
the exact failures are retained. OP Mainnet returned a full pre-state trace and
root-checked state reads. Its complete native offline replay now matches the
observed state root, receipt root and withdrawal storage root. The reference also
checks execution-header rules, body roots, Jovian DA footprint and requests hash.
This workload has **280 candidate accounts, 1,555 storage slots, 7,062 trie nodes
and 171 code blobs**. Twelve nodes required recovery after trie path compression:
`witness_nodes.py` derives compact-path suffixes and admits only exact hashes
already referenced by retained trie nodes. The earlier missing-node failure is
retained alongside the successful replay.

Both the Ethereum benchmark block and OP Mainnet workload passed three fresh
native replay processes. Each rejected missing state, missing code, a modified
withdrawal root and a modified requests hash. The native timing receipts measure
reference execution and validation, **not Cairo proving**. Fork times used by
op-geth match the retained OP configuration for every relevant execution fork;
the embedded and independently retained registry revisions are recorded separately.

The [native reference evidence](evidence/2026-10-29-m5-max/native-reference)
retains compressed replay inputs, access preimages, compiler/dependency/source
hashes and positive/negative receipts (about 3.5 MB). These public-chain witnesses
are retained to make the complete offline replays reproducible; full per-account
proof collections and the raw 15 MB trace remain under the local `block-data`
directory. Paced collection/retry timings include reused successful reads and
public-endpoint throttling, and are not fresh-witness latency estimates.

```sh
gzip -dc autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/native-reference/optimism-input.json.gz \
  > /tmp/optimism-reference-input.json
/path/to/op-reference-execution --input /tmp/optimism-reference-input.json \
  --output /tmp/optimism-reference-result.json
../keth-pinned/.venv/bin/python autoresearch/experiments/evm_keth/qualify_op_reference.py \
  --binary /path/to/op-reference-execution --input /tmp/optimism-reference-input.json \
  --out /tmp/optimism-reference-qualification
```

The official
ZK-PIG witness generator was also located and built at the revision in
`pins.json`; its unmodified chain configuration does not support OP chains.

## Proved OP fee kernel and execution checkpoints

The owned Cairo overlay now constrains the exact op-geth FastLZ length
calculation, Fjord L1 data fees, Isthmus/Jovian operator fees and estimated DA
footprints. Dictionary squashing authenticates the compression table; the
compressed size is computed in Cairo. Full uint256 base fees use exact 384-bit
intermediates and long division, with explicit rejection when the resulting fee
cannot fit uint256. Differential tests cover short inputs, long matches, the
8,191-byte distance boundary, random inputs, cross-limb carries, overflow and
both operator-fee regimes at their integer limits.

The real OP Mainnet block's **34 sequencer transactions** produce a single
**3,130,693-transition** fee-kernel trace. Its **419 public field values** publish
the transaction hashes, fee parameters, gas inputs, compressed lengths, fees
and DA footprints. They match the unmodified op-geth functions and the complete
block's reference checkpoints; DA footprints sum to the header's **2,863,200**.
Three CPU and three Metal proofs all independently verify and are byte-identical.

| Backend | Workers | Trials | Median product process | Median proving | Peak physical footprint |
| --- | ---: | ---: | ---: | ---: | ---: |
| CPU | 8 | 3 | 2.269 s | 2.192 s | 3.20 GiB |
| Metal | 8 | 3 | 1.320 s | 1.238 s | 3.48 GiB |

These process measurements exclude compilation, tracing, conversion and the
independent verifier process; all stage timings are retained. Each backend has
a fresh preprocessing directory retained across its three trials. Metal inherits
the existing disk archive. One compressed 891,374-byte proof and the six complete
benchmark/verifier receipts are retained in
[the kernel evidence](evidence/2026-10-29-m5-max/op-fee-kernel).
Complete OP block proving still requires the deposit/sequencer execution layer,
state authentication, public block statement and derivation integration.

`op_state_fixture.py` reconstructs pre/post state values directly from the
authenticated witness: 280 accounts, 1,555 storage slots, 36 account changes and
105 storage changes in Keth's diff representation. It loads into Keth's state
types and remains rejected by the Ethereum-only driver. Native checkpoints now
cover every pre/post transaction state. Merkleizing those intermediate states
required **three additional sibling nodes** beyond the complete block replay.
Short public secure-path queries recovered them through root-verified storage
proofs. Their exact node hashes, query proofs and checkpoint roots are retained;
the full 19 MB checkpoint file remains local and can be regenerated offline.

```sh
../keth-pinned/.venv/bin/python autoresearch/experiments/evm_keth/complete_op_checkpoints.py \
  --binary /tmp/op-reference-execution \
  --input autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/native-reference/optimism-input.json.gz \
  --access-list autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/native-reference/optimism-access-list.json \
  --supplemental-nodes autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/op-fee-kernel/supplemental-nodes.json \
  --out /tmp/op-checkpoints
python3 autoresearch/experiments/evm_keth/build_op_reference.py \
  --reference-checkout ../optimism-op-batch-reference --target fee-oracle \
  --out /tmp/op-fee-oracle
```

`op_fee_workload.py` builds the exact fee inputs and expected public outputs from
these checkpoints, checking transaction order, state continuity, receipts, the
lazy fee context and the header's DA footprint. `op_kernel_benchmark.py` compiles
the owned overlay, traces it with pinned Keth, checks conversion/program identity,
proves with either existing product and inspects every independently verified
public output. The kernel's complete execution/derivation/block-statement claims
stay false. The retained 34-transaction input and expected output can be proved
again with:

```sh
python3 autoresearch/experiments/evm_keth/op_kernel_benchmark.py \
  --keth-checkout ../keth-pinned \
  --source autoresearch/experiments/evm_keth/cairo/op_stack/fees_main.cairo \
  --input autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/op-fee-kernel/workload-input.json \
  --expected-output autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/op-fee-kernel/workload-expected-output.json \
  --product zig-out/bin/stwo-cairo-metal \
  --oracle tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier \
  --converter autoresearch/experiments/evm_keth/legacy_input_rs/target/release/keth-legacy-input \
  --workers 8 --trials 3 --out /tmp/op-fee-kernel
```

`l1_rollup_batches.py` links configured inbox matches to the verified L1 proof
segments. `analyze_op_blobs.py` verifies KZG bindings, validates OP bit packing,
frame completeness and channel decompression, and reports encoded span metadata.
Its dependency versions are pinned in the script's uv metadata. Reproduce the
offline blob checks with the retained three blobs and trusted setup. The setup's
SHA-256 is checked against the pinned official Ethereum c-kzg source:

```sh
uv run --script autoresearch/experiments/evm_keth/analyze_op_blobs.py \
  --fixture ../keth-pinned/test_data/22615247.json --transaction-index 15 \
  --blob-directory autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-l1-batch \
  --trusted-setup autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/base-l1-batch/trusted_setup.txt \
  --out /tmp/base-batch-characterization.json
```

`collect_rpc.py` retains chain ID, a resolved block and its parent, with optional
ordered receipt collection. `assess_op_stack.py` binds the observation and chain
configuration hashes to explicit execution, derivation, public-statement and
settlement integration requirements. The two retained assessments list the
outstanding work. A gas ratio from the Ethereum fixture cannot establish OP
proving cost; these OP observations are workload characterization only.

```sh
python3 autoresearch/experiments/evm_keth/collect_rpc.py \
  --endpoint https://mainnet.optimism.io --chain-id 10 --block 0x977b291 \
  --out /tmp/op-block-observation
python3 autoresearch/experiments/evm_keth/assess_op_stack.py \
  --observation /tmp/op-block-observation --chain-config /path/to/pinned/op.toml \
  --out /tmp/op-integration-assessment.json
```

Remaining qualification work includes repeated complete runs, worker, chunk
size and monolithic capacity comparisons, a broader Ethereum workload set, an explicit constrained
block/chain statement, OP execution and derivation compatibility, and the
intended settlement verifier. The inherited base also fails the repository's
source-conformance and circuit-provenance gates; formatting has been repaired,
and those failures remain visible. No full repository CI pass is claimed.
Local evidence commits use the documented `--no-verify` checkpoint option from
`CONTRIBUTING.md` because the inherited source-conformance findings reject the
commit hook. This does not waive the gates; disclose it when opening a PR.

## Proved real OP call deposit

The current **v2 statement** adds constrained membership checks over every
finalized persistent account/storage access key, binds initial account storage
roots, and constrains the transaction-created marker set to start empty.
Tests reject hidden BALANCE and SLOAD reads and a forged marker that would alter
SELFDESTRUCT behavior. Thirteen execution cases match op-geth, and malformed
deposit/cached-code tests also pass. All six v2 proofs independently verify and
are byte-identical; they execute **4,937,468 transitions**.

| v2 backend | Median product process | Median proving | Peak physical footprint |
| --- | ---: | ---: | ---: |
| CPU | 5.253 s | 5.113 s | 8.61 GiB |
| Metal | 2.778 s | 2.625 s | 8.45 GiB |

Evidence is in [`op-deposit-kernel-v2/`](evidence/2026-10-29-m5-max/op-deposit-kernel-v2).
This binds persistent read keys and supplied values. Cairo MPT authentication,
the remaining transaction-local state/default-value audit, general OP fork
compatibility and full block proving remain open. The earlier v1 measurement
below is retained separately, including its explicit limitations.

The owned `deposit_main.cairo` program now executes the L1-attributes deposit of
OP Mainnet block 158,839,441. It decodes the canonical `0x7e` envelope, applies
minting and uint64 nonce wrapping, executes Keth's Prague EVM, handles deposit
failure/refunds, and publishes transaction/source hashes, gas, success, nonce,
the environment commitment, and before/after supplied-state-view commitments.
The real result matches pinned op-geth: **46,230 gas, success, deposit nonce
53,604,410**, across **280 accounts and 1,555 storage slots**.

Three trials per backend use 8 workers and canonical security. All six proofs
are byte-identical and independently verified. The program executes
**4,057,477 Cairo transitions** and publishes 15 fields. Compilation, tracing,
conversion and independent verification have separate timing receipts.

| Backend | Median product process | Median proving | Peak physical footprint |
| --- | ---: | ---: | ---: |
| CPU | 4.675 s | 4.538 s | 7.22 GiB |
| Metal | 2.608 s | 2.457 s | 7.50 GiB |

[`op-deposit-kernel/`](evidence/2026-10-29-m5-max/op-deposit-kernel) retains
one proof, all six verification/public-output receipts, compressed input and
independent result, source/build hashes, and the differential test receipt.
`build_op_reference.py --target deposit-oracle` builds the independent oracle.
The four test methods cover canonical integer limits, twelve execution cases
(including invalid intrinsic gas, insufficient value, revert, out-of-gas,
refunds, calldata floor and combined nonce/mint wrap), malformed envelopes, and
rejection of initial cached code that could bypass a Keccak code-hash check:

```sh
python3 autoresearch/experiments/evm_keth/build_op_reference.py \
  --reference-checkout ../optimism-op-batch-reference --target deposit-oracle \
  --out block-data/keth-integration-20261029/op-deposit-oracle-2
../keth-pinned/.venv/bin/python -m unittest autoresearch.tests.test_keth_op_deposit -q
```

`op_execution_workload.py` prepares the input from the complete native replay,
checkpoint-completion receipt and access list. Its output feeds
`op_kernel_benchmark.py` with `--source` pointing to `deposit_main.cairo`.
The committed compressed input and expected output also support offline
reproduction without a new RPC collection.

This is a call-deposit execution kernel. Contract creation is explicitly refused.
General OP precompile/fork compatibility, complete EVM-read coverage, initial
account storage-root metadata binding, Cairo MPT membership and L1 deposit
authorization remain unfinished. The input checkpoint follows pre-transaction
system calls; those calls are still unproved. Full OP block measurements require
the remaining 34 sequencer transactions and these integration steps. The
provenance records every broader block, state-authentication and derivation
claim as false.

The full Python script-contract run completed 2,334 tests with 36 failures,
61 errors and 28 skips; its failure inventory is retained in the merge
qualification directory. Fourteen focused Cairo benchmark contract tests pass.
The inherited global CI failures described above remain unresolved.

## Earlier transport qualification

The [smoke evidence](evidence/validation.json) is deliberately labelled as a
Keth Fibonacci sample, not an EVM block benchmark. Its full CPU path passed
Zig self-verification and independent official Rust verification. Output 144
was extracted; a copy changed to 145 was rejected. The retained compressed
proof was also independently reverified.

```sh
python3 -m unittest autoresearch.tests.test_keth_stwo_bridge -v
python3 autoresearch/experiments/evm_keth/bridge.py audit --keth-checkout /path/to/keth \
  --out /tmp/keth-source-audit.json

tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier verify \
  --proof autoresearch/experiments/evm_keth/evidence/keth_fibonacci.proof.bz2 \
  --channel blake2s --proof-format binary --result /tmp/keth-proof-verdict.json
```

`bridge.py trace` and `bridge.py prove` expose the individual trace and proof
boundaries. `export_smoke_pie.py` reproduces the earlier sample using Python
3.10 and `cairo-lang==0.13.5`. Output paths must be fresh.
