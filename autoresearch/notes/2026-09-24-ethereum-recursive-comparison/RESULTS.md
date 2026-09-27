# Accelerated Ethereum authentication with recursive completion

These are real guest proofs of EIP-1559 transaction authentication, not block
validation. Both adapters run the shared typed/RLP parser, reconstruct the signing
payload, enforce signature encoding/low-S, recover the public key and derive the
sender. The public result binds a version, count, Keccak input commitment and an
ordered commitment to transaction hashes and senders. Runtime inputs are identical.
Expected senders are derived independently from fixture signing keys, rather than
from the guest's parser/recovery. No EVM execution, state transition, MPT or SHA
workload is included in these measured rows.

## Verified observations

M5 Max, AC power, CPU, ReleaseFast/release, 16 requested proving workers. Each
measurement is one fresh-process observation, not a median. No competing build
or proof ran. The headline interval includes process startup, setup, proving,
verification and artifact persistence on both sides. Raw phase intervals have
different setup boundaries and are not substituted for this headline.

| Transactions | STWO-Zig process wall | ZisK process wall | STWO peak footprint | ZisK peak footprint |
|---:|---:|---:|---:|---:|
| 1 | **52.679 s** | **420.177 s** | 30.44 GiB | 45.16 GiB |
| 4 | **54.230 s** | not measured | 31.28 GiB | — |
| 16 | **no completed root: worker budget exceeded** | **425.379 s** | 55.68 GiB at failure | 45.24 GiB |

Local successful roots use a complete execution leaf and one actual native STARK
recursive wrapper. They authenticate the complete execution span and public I/O.
The local root is encoded, decoded and independently verified after releasing
the proving worker and preparation. ZisK produces its native aggregated final
STARK and verifies against the guest's BLAKE3 program key. Neither includes an
extra on-chain SNARK wrapper. The architectures need not use equal leaf counts.
This does **not** qualify our multi-leaf tree on this workload; the explicit
two-leaf attempt below failed its resource budget.

**Native configurations, not security-normalized superiority:** local leaf and
wrapper both use 70 queries / 26 PoW bits. The active peer base AIR keys use
211 queries / 24 PoW bits, with its final key using 106 / 24 and a different
field, FRI schedule and blowup. See `active-peer-security.json` and the official
key provenance retained in the adjacent guest-e2e campaign. Query counts are not
interchangeable soundness targets across these protocols.

The 16-transaction peer run enables native debug stage timers; the one-transaction
peer run uses ordinary info logging. The near-flat timings are observations, not
a statistically established incremental cost or profiler-free speed ratio.
Requested RAYON/OMP limits are 16; ZisK also uses a separate recursive witness
pool. This is not a strict global sixteen-thread cap on every internal pool.
System swap readings are retained per invocation; the failed local larger run
increased system swap usage. Successful-run footprint is process-wide and is
distinct from the local worker's routed allocation budget.

## Where local time goes

| Stage | 1 transaction | 4 transactions | 16 transactions |
|---|---:|---:|---:|
| Accelerated guest instructions | 12,419 | 38,037 | 140,708 |
| Observed local Keccak-f calls | 6 | 22 | 87 |
| Observed local recovery calls | 1 | 4 | 16 |
| Leaf proving | 4.811 s | 5.389 s | 6.597 s |
| Leaf capture verification | 0.044 s | 0.042 s | 0.041 s |
| Recursive preparation, excluding those leaf stages | 9.006 s | 9.815 s | not separately retained |
| Parent proving | 32.052 s | 32.645 s | failed in FRI |
| Final decoded-root verification | 0.009 s | 0.009 s | no root |
| Root artifact | 888,734 B | 893,090 B | none |

These stages do not sum to process wall: witness/admission, parent key/worker
initialization, encoding, cleanup and startup are also included in the headline.
For one transaction the internal transaction interval is 51.932 s; process wall
is 52.679 s. Both raw values are retained rather than labelled interchangeably.

The 16-transaction leaf and its verification succeeded. Its parent preparation
retained 8,485,429,640 bytes, versus 4,792,166,572 for one transaction. Parent
proving hit the **configured 48 GiB worker limit** at FRI; it did not produce a
verified root. This is not evidence of a cryptographic failure or proof that a
larger budget could never finish. Preparation storage is outside that worker
budget. The arithmetic circuit row count grew only from 1,430,772 to 1,435,336,
so arithmetic row count alone does not explain the retained-byte increase.

Fresh preparation-only diagnostics reproduce both retained-byte totals exactly.
The breakdown identifies **BLAKE3 G rows as 87.89% of the storage increase**:

| Recursive row family | 1 transaction | 16 transactions |
|---|---:|---:|
| G active/fixed rows | 6,981,240 | 10,515,288 |
| G padded main rows | 8,388,608 | 16,777,216 |
| G main columns | 90 | 90 |
| G retained bytes | 3,466,700,400 | 6,712,778,352 |
| Byte-route retained bytes | 418,199,244 | 669,775,800 |
| XOR retained bytes | 148,534,944 | 273,431,712 |

The G main-column allocation doubles at the power-of-two boundary. This is a
measured recursive hash-proof representation/padding bottleneck, not evidence
that the raw BLAKE3 compression implementation is slow. `geometry-comparison.json`
retains all twenty row families. These diagnostics reprove/verify the leaf and
prepare the parent, but deliberately do not claim a new final root or latency.

An earlier one-transaction attempt artificially split execution into two leaves.
Both leaves verified, but its parent exceeded the same 48 GiB limit during
composition commitment. Retained preparation was 9,513,701,596 bytes and process
peak footprint was 58,946,533,480 bytes. Its four-worker settings and failed
completion exclude it from the headline comparison. Its binary/source/log are
retained as `initial-two-leaf-host*` and `local-batch-1-prove-initial*`.

## ZisK phase attribution

The successful 16-transaction peer run used **16 base AIR instances**, including
native Keccak, arithmetic and DMA AIRs. The execution-only plan and proof log
confirm acceleration; these are not unpatched software hash/curve guests.
ZisK executed 114,192 internal steps (7,428 for one transaction). These counts
use a different ISA and cannot be compared as equal units to RV32IM cycles.

| Recorded stage | Time |
|---|---:|
| Guest execution | 0.039 s |
| Contribution calculation | 15.619 s |
| Base proof tasks, sum | 92.074 s |
| Inner recursive proof tasks, sum | 304.683 s |
| Final recursive proof task | 8.951 s |
| Combined base/inner phase, wall | 396.827 s |

The logged base-proof and inner-recursive-proof intervals do not overlap in this
CPU run. Witness generation does overlap/wait: recursive witness timers report
about 0.930 s of net work, but their union of elapsed spans is about 285.469 s
including waits. That latter value is **not** 285 seconds of witness computation.
`summarize.py` retains summed task durations, interval unions and overlap separately.
CPU interval attribution does not establish the scheduling behavior of CUDA.

Many active peer AIR domains contain 1–4 million rows at these pinned settings,
even for the small batch. This supports investigating fixed instance/recursion
costs and batching. Neither these small batches nor the previous software SHA
chain establish ZisK's Ethereum-block throughput. The 16-transaction final proof
is 831,536 bytes and passed both key-bound verification and the public-output check.

## Qualification and reproduction

- Two focused parser unit tests pass, covering RLP canonicality, integers,
  scalar range and access-list structure.
- Fixture generation checks every truncated input for all five batch sizes,
  plus malformed-type/trailing-data rejection, against the shared parser.
- Both real guests pass all five valid sizes and five negative execution cases:
  bad type, bad parity, zero r, high s and noncanonical RLP. These negative checks
  are **execution tests**, not negative proof results (`guest-qualification.json`).
- ZisK source checkout remains clean at
  `5c5f81c96929abed88894473ec6060b1b545b5c5`; official BLAKE3 key and custom Rust
  toolchain are reused from `../2026-09-24-zisk-guest-e2e`. New host/guest dependency
  locks are retained. No peer algorithm or security parameter was patched.

Build with `build_guests.py`, `build_fixtures.py`, `build_local.py` and
`build_peer_host.py`. Run `test_common.py` for parser tests. With a fresh label:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-recursive-comparison/run.py local batch-1 prove repeat1
python3 autoresearch/notes/2026-09-24-ethereum-recursive-comparison/run.py peer batch-1 prove repeat1
ETH_AUTH_PROFILE=1 python3 autoresearch/notes/2026-09-24-ethereum-recursive-comparison/run.py peer batch-16 prove repeat1
python3 autoresearch/notes/2026-09-24-ethereum-recursive-comparison/summarize.py
python3 autoresearch/notes/2026-09-24-ethereum-recursive-comparison/run.py local batch-16 prepare diagnostic1
```

The driver serializes builds/proofs, refuses retained-result overwrites, records
binary/ELF/input/oracle hashes under the build lock, preserves resource/power data
and kills the whole process group on timeout. The unfinished initial four-worker
peer run was deliberately stopped when fixture worker defaults were corrected;
it is not a result. The first local build and peer host build each exposed
harness integration errors, corrected before any successful proof measurements.

## Roadmap supported by these results

1. Reduce BLAKE3 G row storage, its power-of-two padding and peak live memory.
   Benchmark proved compression/round work against ZisK's hash-proof machinery;
   native compression throughput alone does not measure this cost. The measured
   limit arrives after a valid accelerated leaf, so faster guest execution alone
   will not make the larger root complete within the same budget.
2. Reduce fixed recursive preparation/proving cost; verify changes against these
   retained inputs and final-root checks. Preserve q70/PoW26 throughout.
3. Qualify useful multi-leaf aggregation and bounded branch scheduling on this
   workload, not only the earlier six-cycle tree fixture.
4. Add state-witness/MPT verification, then complete the local SHA-256 precompile's
   production dispatch/memory linkage and benchmark SSZ/EVM SHA separately.
5. Later, run the peer on Linux/NVIDIA with its optimized assembly/CUDA/hint
   paths for a deployment-performance comparison. The current Mac uses CPU/emulator plus
   native precompiles; it is **not ZisK's full hardware-capability result**. A GPU
   run is explicitly deferred by the user; this campaign is CPU-only.
