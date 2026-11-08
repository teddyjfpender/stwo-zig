# RV64 GPU resource and development contract

This is the delivery contract for the GPU hygiene and developer-experience
work started on 2026-11-08. It replaces the performance campaign as the active
work item. It does not change the proof protocol or promote GPU-native defaults.

## Ownership and lifetime

The installed GPU-native request path is the scope of the storage invariants
below. Compatibility/reference jobs retain explicit host-result and owned-span
modes until their complete replacement scope passes. A default-path proof gate
alone does not establish native readback or event-ownership behavior.

| Resource | Owner | Borrow ends | Construction / reclamation |
|---|---|---|---|
| Immutable class geometry, FIXED, twiddles, codecs | installed class / worker | after every dependent job settles | install; service teardown or unpinned cache eviction |
| Captured block inputs | capture ring | last device consumer completes | bounded capture slots; stream-ordered release |
| Staged job inputs and pinned metadata | worker parity / placement | job completion | reserved pools; stream-ordered reuse |
| Job scratch and private device slab | worker arena | last enqueued consumer | declared footprint; arena reuse |
| Host-readable job result | worker pinned slab mirror | `finish` returns | explicit job readback policy |
| Device-published proof and verdicts | request slab | request publication / abort completes | installed two-parity request storage |
| Streams and dependency / timing events | installed worker or factory | all dependent work quiesces | install; teardown, never an implicit request allocation |
| Graph executable | worker / installed class | all launches complete | bounded cache; invalidate when captured addresses change |

`api.Footprint` is the authoritative job resource contract. It must distinguish
device scratch from the host observation of that scratch. A device-published
node must not download a private slab merely because a host-result job uses
the same kernels. Changing observation policy must preserve device allocation,
verdict checks, encoding and proof bytes.

Memory declarations must use the same ordered buffer sizes as allocation.
Sequential phases use a maximum; simultaneously live resources add. Checked
word arithmetic rejects overflow before allocation. Logical schedule high-water,
allocator high-water, physical process peak and capacity enforcement are
different evidence and must retain distinct names.

## Request path and instrumentation

Installation constructs authorities, warms immutable resources and reserves
bounded storage. The request path captures block-derived inputs, stages,
enqueues, waits at the request boundary and publishes checked device outputs.
Class misses and insufficient capacity fail explicitly. No unreported CPU or
legacy fallback is permitted.

Host callbacks, ordinary job readbacks, final request readbacks and peer-copy
transport are separate operations. CUDA can stage a peer copy through host
memory when direct P2P is unavailable. Attribute such traffic by CUDA
correlation ID; do not call every D2H operation a CPU proof readback, or call
two top-level readbacks the complete CUDA transfer census.

Native stage and node ranges must be visible in traces without introducing
CUDA events or waits. Host range duration is enqueue time; GPU projection or
activity intervals establish device work. Missing trace tables, ambiguous
correlation or absent stage coverage are reported as unavailable, never zero.

## One validation authority

The shared validation implementation owns runtime/binary hashes, frozen proof
payload selection, parity, receiver acceptance and rejection-corpus completeness.
The commit gate, controlled comparison and basket must consume it. A resource
rejection in a negative test is a limitation, not semantic rejection evidence.
Partial or failed comparisons cannot produce a speedup verdict.

Correctness receipts identify source, driver, receiver, runtime, workload,
profile and environment. Timing qualification additionally requires the
canonical quiet interleaved comparison, deferred verification and its physical
guard. New-block setup remains separately charged. This cleanup does not
certify the historical M8 speed targets or Rust-oracle parity beyond the
specific evidence actually collected.

## Development workflow and completion gates

Use the existing repository entrypoints: `scripts/ci.py --fast` for static
checks and `scripts/dev_test.py` for package-owned focused tests. Extend their
routing instead of adding a second test launcher. Host contract tests do not
require a GPU. Pod compiles use a build lock; hardware gates own the GPU lock.
Do not sync source underneath a live build, gate or measurement.

Delivery requires all of the following:

1. The resource/readback contract is executable, has boundary/failure tests,
   and is used by workers and the native node adapter.
2. Allocation and budget calculation share the node's held-buffer schedule.
3. Installation/request boundaries and remaining legacy paths are documented
   and checked; remove only replacements whose complete acceptance scope passes.
4. Gates and benchmark tools share validation primitives and expose incomplete
   evidence, pin drift and nonsemantic rejection limitations consistently.
5. Native stage/node ranges and a tested CUDA activity census distinguish
   API calls, device activities, peer fallback, host waits and unavailable data.
6. Focused resource, driver, native, truth and outer tests are discoverable
   through the existing developer workflow; changed tools are routed into CI.
7. Static checks, relevant host tests and the bounded full-proof regression
   gates pass. No repeated performance-tuning campaign is part of this task.
8. Owner documentation, a compact evidence receipt and a reviewable committed
   change describe actual validation and any remaining limitations.

Oversized runtime files are decomposed by ownership boundary as changes reach
them. File moves, wrappers and generic abstractions alone do not satisfy these
gates. Historical receipts remain recoverable; stale claims in current owner
documentation must be corrected.
