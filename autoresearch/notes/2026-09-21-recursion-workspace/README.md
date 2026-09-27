# Persistent recursive workspace checkpoint

This continues the [four-part implementation goal](../2026-09-21-recursion-implementation/README.md).
The goal remains active. This checkpoint establishes cross-request ownership;
it does not complete persistent AIR preparation, circuit fusion, direct-layout
witness production or the separate parameter experiment.

## Implemented

The CPU and Metal detached-parent producers accept an explicit pinned batch:

```text
CPU:   producer --batch requests.json <sha256>
Metal: producer --aot-bundle <dir> --aot-manifest-sha256 <pin>
                --aot-profile recursive-framework-v1
                --batch requests.json <sha256>
```

The version-1 JSON contains `session_byte_budget`,
`retained_scratch_byte_limit`, and `requests` (arrays of ordinary producer
arguments starting with `--profile`). Admission limits the manifest to 1 MiB,
1–64 requests, a nonzero transform budget of at most 256 MiB, and at most
512 MiB retained scratch. Each request requires an independently pinned parent
key. The batch hash and arguments are checked before initializing Metal.

One batch retains one authenticated Metal runtime and one worker-owned workspace.
The workspace uses the existing `Engine.Session`, validating the exact PCS
configuration and required transform domain. Compatible requests share its
immutable twiddle table. Incompatible configurations or larger domains replace
the single cached plan, with eviction before allocation to respect its budget.
Every proof still gets fresh channels, key admission, witnesses and components.
The ordinary single-request command remains available through the same code.

A request-scoped quotient-scratch arena uses the existing scheme allocator hook,
resets only after scheme/evaluator destruction, and caps retained capacity.
If shrinking fails it frees all scratch. **Neither the measured CPU nor Metal
profile allocated through this hook**: retained capacity was zero. No scratch
reuse benefit is claimed. The existing typed evaluator uses this hook only when
it must materialize a different quotient domain; the measured geometry already
has suitable committed evaluations. This is not a resident trace-buffer cache.

The batch's internal elapsed counter excludes final workspace destruction and
runtime initialization/shutdown. The external process timers below include them.
The retained scratch limit is not an OS memory limit for the entire request.

## Qualification

ReleaseSafe CPU and Metal producer builds pass. Three focused workspace tests
pass: compatible reuse and domain/config replacement; over-budget rejection and
recovery; failed scratch shrinking followed by complete release. Tests also
exercise lease exclusion and no-lease rejection. Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-recursive-parent-workspace -Doptimize=ReleaseSafe --summary all
```

| Diagnostic | Requests | Transform builds | Complete process seconds |
| --- | ---: | ---: | ---: |
| Metal, repeated qualified root | 3 | 1 | 16.368327750 |
| CPU, repeated qualified root | 2 | 1 | 17.828053209 |
| Metal, all seven parents with distinct keys and fresh parent dependencies | 7 | 1 | 39.445728833 |

All 12 batch proofs independently verified **after batch process exit**, matching
the original qualified key, claim and proof bytes. The original single-request
Metal route also produced an independently verified byte-identical proof: 13
fresh proofs total. Wrong batch pins and invalid budgets explicitly rejected.
The measured profile remains `recursive_q193_v1`; no security parameter changed.

The first Metal batch reports 4,396,957,696 bytes maximum RSS and 5,520,675,112
bytes peak footprint; these are distinct OS measurements. The seven-parent batch
retains previously admitted leaves, so this is not full-program production.
No builds overlapped these timed batches. These are single diagnostic observations,
not alternating statistical comparisons. In particular, 39.45 s versus the earlier
39.67 s serial-process diagnostic supports **no meaningful speedup claim**.

`git diff --check` passes. Source conformance still reports the same 103 existing
repository-wide failures; none names the new workspace/batch/scheduler files.
The earlier failures remain outside this focused goal.

## Next: cache the expensive preparation authority

The modest result rejects the idea that transform/runtime setup alone explains
the latency. The identified next boundary is
`captured_fri_owned.zig` constructing `pcs_deep_circuit.Prepared` for each child.
That owner already separates an immutable, profile-authenticated graph from
proof-dependent evaluation values. Reuse needs explicit owned leases, complete
profile matching, a byte budget and request-independent storage. Carry this
owner through child capture and PCS preparation rather than adding a global
cache or retaining old witness values. Inactive-lane authority expansion remains
another measured cost. Fixed-commitment reuse and preparation/proving overlap
are also unfinished parts of requirement 1.

Evidence retains raw logs, independent receipts, manifest inputs, replay scripts,
source snapshots, binary pins and source hashes. Full proof bundles remain under
`/tmp/stwo-recursion-workspace-probe-20260921`. CPU and Metal executables are under
`/tmp/stwo-recursion-workspace{,-cpu}-20260921`. `sha256-manifest.json` pins this
checkpoint; nothing has been committed or pushed in this phase.
