# Parking sealed MAIN coefficients

`--park-retained-main` is an optional producer-only storage control. It changes
no constraints, statement, transcript, geometry, roots or proof bytes. Default
`Store.init` keeps its existing mapped-file behavior; `Store.initParked` selects
unmapped storage until stage2 needs the sealed coefficients. Receivers reject
the producer flag and need no scratch files.

The core `file_backed_allocator.ReservedFile` is the single authority for
exclusive temporary-file creation, immediate unlinking, physical disk-block
reservation and length validation. Both the existing mapped allocator and
parking use it. Scratch files are process-local native representations, not a
portable proof/checkpoint format. Linux/macOS are the supported platforms; this
receipt executes on macOS.

Parked spill validates ownership, shape and non-overlapping native allocations
before reserving disk. It allocates only per-column metadata, streams the existing
native coefficient slices directly to an unlinked FD and syncs the file. It then
releases the original native owners and replaces both coefficient and compact
column views with empty slices. Logs, column order, Merkle state and commitment
roots remain available. No initial full file mapping or second wide coefficient
arena is created. Allocator caches and the kernel's clean file cache may retain
physical pages independently; parking is not a promise to reclaim all host RAM.

Each move-only teardown owner keeps its FD, small offset/log metadata, original
allocator and managed-budget lease. A Store stays at a stable address and outlives
its trees. The supplied allocator is the original tree owner; unrelated Scheme
container allocations retain their ordinary caller lifetime.

Restore checks the teardown callback, then numeric identity in that Store's live
owner registry before interpreting any callback context. It checks descriptor
identity, counts, offsets, native/evaluation logs, root and safe-invalid view
state. Only then does it mmap the same FD read-only and publish all compact views.
It uses no fixed-address mapping, witness generation, Tape/VM replay, interpolation
or recommitment. The ordinary downstream composition/sampling FFTs still run.
A restore failure leaves the parked tree retryable. Forgetting restore makes the
ordinary Scheme polynomial-view builder reject empty coefficients with
`InvalidLength`. FD/map teardown and reservation release run through the existing
PCS destruction barrier, including abandoned and failed workers.

Both canonical service workers and the original Stage1Worker remember the actual
Store used by a successful spill. They restore MAIN after INTER commit and before
proving. Root/shape checks at the complete-Manifest barrier inspect only retained
metadata. Stage2 accepts no caller-supplied challenges. Existing post-draw worker
errors remain terminal; the lower-level restore operation itself is retryable.

Disk reservations and live/peak mapped-byte leases are reported separately.
Mapped accounting is serialized with parking mmap/unmap. These counters describe
owned mappings, not process RSS or private memory footprint.

The focused suite has 22 actual runtime tests. It covers empty parked views,
missing restore, foreign callback/context/Store, descriptor and late-log changes,
native alias preflight, both metadata allocation failures, disk-budget refusal,
FD creation/length errors and retry, abandoned cleanup, actual FD close, source
budget lifetime and existing allocator alignment/realloc behavior. Complete q70
mixed CPU/Keccak/ADD/DOUBLE bundles, claims, public requests, proof files and RAM
sidecars equal ordinary controls at one and two worker lanes. Independent fresh
setups verify them. The original Stage1Worker also has complete proof parity.

Two real schema4 prefix4 runs used the same frozen binary, pinned ELF/input and
16 workers (two lanes of eight). Both producers and separate fresh receivers
passed. All four CPU proofs, three truth proofs, `bundle.json`, `cells.bin`,
`roster.json` and `cost.json` are byte-identical. They cover 16,777,212 instructions
and explicitly remain prefixes, not complete-block claims.

| Observation | Mapped control | Parked |
|---|---:|---:|
| Peak reserved native MAIN bytes | 6,235,406,336 | 6,235,406,336 |
| Peak retained mapped bytes | 6,235,406,336 | 3,089,743,872 |
| Final reserved / mapped bytes | 0 / 0 | 0 / 0 |
| Process maximum RSS | 22,647,324,672 | 18,935,676,928 |
| Darwin peak memory footprint | 16,421,604,120 | 16,438,854,120 |

The original mapped run attached every retained file; the parked run restored at
most the active worker lanes. Charged memory footprint was essentially unchanged. Other
engineering/proving processes were active, so these are functional/memory
observations, not a controlled timing comparison or full-block peak claim. The
source is `d33d66521` plus this storage-only slice; newer schema5 measurements
must be qualified separately. Full 25-shard memory evaluation is a follow-up.

Exact source/tool/input and gate/artifact pins are recorded in
`vectors/reports/rv64-word16-execution-20261101/retained-main-parking-v1.json`.

## Current LS7 integration (qualification in progress)

The isolated port starts at `fe3b29fc0`. It preserves the current N-lane scheduler,
per-lane worker budgets and admission estimates, 64-column streaming commitments,
program metadata cache, and owned CPU/truth MAIN/INTER transfers. In particular,
the worker change is only retention of the actual Store and restoration after
INTER commit; the older worker implementation is not substituted wholesale.
Parking remains an explicit producer-only flag, off by default.

The accounting has three distinct meanings. `limit_bytes` is a hard limit on
live reserved native backing storage, enforced before file creation/ownership
transfer. `live_mapped_bytes` and its peak count actual retained mappings while
under the Store's mapping mutex; they are measurements, not a RAM limit. The
scheduler memory cap is admission against per-proof estimates of in-flight work,
not an allocator-enforced bound on RSS, retained mappings, cached allocations or
kernel file cache. An oversized proof may be admitted alone. Parking does not
turn this soft scheduling cap into a hard host-memory guarantee.

The historical schema4 receipt above remains evidence for the recovered source,
not a current-shape result. Fresh LS7 tests/prefix receipts will be pinned
separately before promoting this optional path.
