# RV64 GPU resource and development contract

This is the delivery contract for the consolidation and productionisation
phase directed on 2026-11-08. The canonical checkout is
`/Users/theodorepender/Coding/stwo-zig`, on `codex/rv64-gpu-hygiene`.
The initial resource/validation checkpoint is `4a4d01bd5`; it is an input to
this phase, not its completion. The ordered promotion, deletion and developer
requirements below extend the original hygiene gates. Proof protocol and
security requirements remain binding throughout.

## Productionisation acceptance and subtraction budgets

Every change records code lines added/removed/net, flags added/removed/live,
scripts added/removed and receipt files added/archived. Code, documentation
and evidence totals are separate. The default cleanup budget is net code
growth at most zero and no additional live flag or top-level script. A
positive code budget must identify the new owner or invariant, explain why
existing code cannot provide it, and include its tests in the reported cost.
Moving code into another production directory does not count as deletion.

The starting commit census is `4a4d01bd5`: 2,158,099 code lines in the
source/script/build/tool inventory, 14,945 tracked receipt files and 69 local
M8/M9 branches. There are 294 distinct `STWO_RV64_*` literal names in code,
including 103 M7/M8 names; these are reference counts, not a resolved live
flag registry. The initial checkout inventory contains 163 worktrees.

| Change | Budget / exit condition |
|---|---|
| Consolidate working copies | 163 to 1 registered worktree; preserve every head, local change and non-cache ignored artifact before retirement; net production code growth 0 |
| Flag authority | One generated registry and CI rejection of undeclared flags; fewer than 60 live RV64 flags; each M7/M8 switch is promoted or removed; initial positive implementation budget at most 350 code/test lines, justified by the new CI invariant |
| Static retirement | Delete the 150 unreachable scripts after preservation; resolve all starting non-conforming paths by fixing or deleting owners, with zero new baselines or ceiling increases |
| New-block setup | Reuse the installed class builders in one explicit setup-miss path; budget 0 net code lines unless a bounded positive exception names its ownership invariant and tests; no extra feature switch |
| Legacy sweep | Inventory and remove the complete retired paths after promotion; planning estimate 20–30k code lines removed, with actual measured totals and no retained forwarding implementations |
| Evidence and branches | Archive old receipt folders and stale M8/M9 branches under tagged history; retain only current receipts in the active tree; report exact file and branch reductions |
| Developer interface | Three documented entrypoints at the top of jobs/README.md; no additional top-level launcher |

Promotion and deletion occur in this order:

1. Run the canonical quiet interleaved 3+3 comparison of GPU-native and the
   current default on **24628607 and 26235168**. Pin the final binaries,
   runtime, inputs and environment; require parity, fresh CPU acceptance,
   deferred verification and the physical process-budget guard.
2. Land the new-block setup-miss path. Charge setup and report new-block
   latency separately; same-block warm results are insufficient.
3. Pass the complete 15-block GPU-native basket using the regression entrypoint.
4. Promote GPU-native to the default only with the required accepted evidence.
5. Delete both hybrids, feeder/provider, the legacy owner-callback path and
   their flags and active receipts in one coherent sweep. Archived history
   stays recoverable. Admission and two-lane are already frozen by the plan
   of record and may be retired earlier where a dependency audit establishes
   no live consumer; each deletion batch requires `dev_test.py` and one
   default `rv64_gate.sh` result.

Archive publication must precede remote branch retirement. The
[recovery index](rv64-archive-index.md) records the published refs, literal
branch list and independently verified off-laptop recovery location.

After default promotion, the first performance work addresses late feeding:
the user-reported diagnostic counters are approximately 9.65 seconds of host
enqueue and 5 seconds gated per GPU, not a new qualified latency measurement.
Use native ranges to establish actual waits in capture streaming, per-job
host prestage and whole-node graph replay. Then pursue the architectural
steps in handoff section 5. Kernel tweaks are outside this sequence.

V04's old resource-only rejection is closed by the semantic rejection gates
in checkpoint 7. Physical memory peaks, production new-block latency,
the new GPU-native basket, whole-node graph replay and a qualified speedup
remain open until separately demonstrated. Do not infer them from the
initial bounded proof gates or the CUDA-call census.

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
Until the setup-miss path passes, class misses fail explicitly. Its replacement
must own admission and setup before dependent enqueues, expose that cost and
refuse insufficient capacity. No unreported CPU or legacy fallback is permitted.

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
7. Static checks, relevant host tests, bounded full-proof regressions and the
   ordered canonical/basket promotion gates above pass.
8. Owner documentation, a compact evidence receipt and a reviewable committed
   change describe actual validation and any remaining limitations.

Oversized runtime files are decomposed by ownership boundary as changes reach
them. File moves, wrappers and generic abstractions alone do not satisfy these
gates. Historical receipts remain recoverable; stale claims in current owner
documentation must be corrected.
