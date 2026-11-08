# R1 local Source + MAIN commitment admission

Status: CPU-tested allocation models; runtime candidate is default OFF and not
GPU-qualified. No request-time improvement, whole-process peak, global admission
coverage or completed R1 gate is claimed by this package.

The local envelope contains CPU projection scratch/evaluations/optional compact
input/cold ROM, the core ledger, every retained family/LS/boundary input, every
MAIN output, bridges, bulk and sponge common workspaces and row inputs, ZBB/DWORD,
and MAIN trace commit while Source remains alive. TC geometry comes from the
same complete column roster. Each allocation rounds independently using the
existing 32 MiB large-chunk / 512-byte small-allocation policy. Compact input
retires at the joined projection boundary; Source and TC workspace retire after
MAIN adoption; coefficients survive until the worker/PCS owner is destroyed.

The before-allocation guard checks phase, scope, size, kind and inventory
multiplicity. It allows only the modeled cold-ROM allocation to be absent on a
cache hit. This addresses temporary allocations that a joined-end snapshot would
miss. The physical snapshot gate adds existing arena retention to the class
envelope, checks the static byte cap and virtual capacity, then checks joined
retention. It is restricted to CPU0 while all other request GPU work is deferred
until the early helper joins. It must not admit multiple concurrent segments.

With `STWO_RV64_EARLY_NATIVE_MAIN=1`, TC freezes its allocation schedule, and the
pool supplies its long-lived allocator to CPU projection and TC caches/headers.
That routes actual host payload allocation/free through the existing service
Recycler/SharedHostBudget. Compact pack threads use explicit 1 MiB stacks; their
derived count is externally reserved before early work and released after join.
The RAM/early-MAIN helper's separate 2 MiB stack belongs to the orchestrator.
This does not set the global planner's `host_cost_known` or close its other stages.

Pod CPU tests (ReleaseSafe): combined model/capacity/guard/dependencies 31/31.
Earlier isolated runs were Source/CPU/TC/dependencies 25/25, capacity/dependencies
28/28 and guard/dependencies 27/27. These share dependency cases and must not be
added as independent tests. Raw logs are adjacent. The final source is formatted
after these CPU runs; no proof or runtime qualification is inferred from them.
Runtime source, typed adapter and end-to-end GPU proof qualification are separate
gates. The existing accepted runtime remains the performance reference.
