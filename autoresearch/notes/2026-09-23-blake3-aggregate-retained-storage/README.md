# Canonical aggregate retained-column storage

SUPERSEDED: User deferred expanded Ethereum proving. The queued mapped canonical run was cancelled before starting; parent-specific storage wiring was removed from live source. Source copies below are an unqualified experiment, not the current implementation. Existing diagnostic compatibility checks remain queued using ordinary storage.

Baseline: canonical q70/PoW26 two-segment Ethereum aggregation failed at interaction
commitment with ParentWorkerHostBudgetExceeded. Tracked peak 51,522,018,090 bytes;
worker limit 51,539,607,552 bytes (48 GiB). Prepared rows outside that cap retained
11,906,171,864 bytes. Seven of eight harness tests passed; the aggregate did not.
See canonical-host-budget-failure.log. This supersedes the previous running status.

Implemented, not yet qualified: the parent workspace/worker now accepts an optional
borrowed retained-column allocator, passed to the existing PCS streaming-storage
path with coefficient retention disabled. Its lifetime covers synchronous proof
requests; outputs must not retain it. Defaults remain ordinary host allocations.

The Ethereum aggregation fixture explicitly chooses private temporary file-backed
column storage with a separate 64 GiB allocation cap. Its host worker cap stays
48 GiB canonical / 24 GiB diagnostic. File-backed allocations are EXCLUDED from
that host allocation cap; mapped pages can still contribute to RSS and page-cache
usage. This is capacity qualification on the current host, not a speedup claim.
The fixture checks mapped allocations return to zero before artifact verification
and logs the separate peak. Scratch files are preallocated and unlinked by the
existing allocator. Available disk at setup: 312 GiB.

Queued diagnostic command:
```
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=adjacent segments' -Doptimize=ReleaseSafe --summary all
```
Log: /tmp/blake3-owned-segment-pair-aggregation.log

Queued canonical command:
```
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-ethereum-canonical-aggregation -Doptimize=ReleaseSafe --summary all
```
Log: /tmp/blake3-ethereum-canonical-aggregation-mapped.log

Both runs also include shared segment/job constructors and earlier child-owner
release. No passing result is claimed for those combined changes yet.
