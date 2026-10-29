# EVM block proving with Keth and Stwo Zig

This owner-operated experiment feeds Kakarot Labs' **Keth** Cairo execution
programs into the existing Stwo Zig CPU/Metal products. The measured block
bundle uses a narrow adapter for the pinned Keth execution witness.
Released AIRs, proof protocols and verifier pins are unchanged.

The first real workload is Ethereum mainnet block **22,615,247**, hash
`0x0497f69549701d578c67a43951f9e4fcb92b1691b9f6bbdfa63a17bc41d3971e`:
26 transactions, 16 withdrawals, and 1,331,413 gas. Its witness is committed in
[the pinned Keth source](https://github.com/kkrt-labs/keth/blob/e90c0a51699182f140e51c94d09ff9045c194769/test_data/22615247.json).
An independent Ethereum RPC snapshot confirms the header hash, state root,
transaction count and gas usage. The header was also checked with Ethereum
RLP encoding and Keccak, including its parent link.

## Integration

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
visible and never qualify. Larger transaction chunks can exceed this host's
8 GiB memory limit. The entire monolithic `main` trace also exceeded this limit;
segmentation is required here. No unsuccessful run is reported as a block proof.

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
