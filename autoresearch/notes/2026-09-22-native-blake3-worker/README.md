# Persistent native BLAKE3 proving worker

Worker(Backend) owns one admitted Plan, reusable Workspace, SharedHostBudget and
explicit WorkPool. It binds that pool during fixed-plan construction and proving,
including the serial configuration, preventing accidental global-pool discovery
in those calls. One worker rejects overlapping requests; mutable workspace and
pool state are not shared between simultaneous proofs. Production worker-count
selection still belongs to the execution admission policy.

The worker routes plan, scratch, proof and pool-metadata allocations through its
host budget. Returned artifacts retain a budget lease. Verification transfers the
lease to its capture on success; rejection destroys proof allocations before
releasing the artifact's lease. Final budget release checks that live routed
allocations are zero. Thus proofs and captures can safely outlive the worker.
The underlying budget remains heap-stable and synchronized across threads.

This cap is not total RSS. On macOS/Linux, Merkle layers use a separate
size-routed allocator (small layers on smp_allocator, large layers on mmap),
which bypasses the caller allocator. Thread stacks, worker/control metadata,
borrowed preparations and allocator overhead also need separate reservations.
These exclusions must be accounted for before claiming total-memory admission.

## Qualification

```sh
zig test src/prover/host_budget_allocator.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Both terminal exit 0. Budget unit tests: 5/5 passed, including cross-thread free
and a retained budget lease surviving original-owner release. Native gate: 4/4
steps, 3/3 tests, 37 s / 2 GiB; compile 1 min / 5 GiB. No allocator leaks.

The real gate rejects invalid worker counts, an insufficient construction budget,
and an already active worker. Two complete proofs reuse one explicit two-worker
pool, authenticated fixed commitment and workspace. Existing row-mutation,
scratch failure/aliasing, codec and independent verification checks remain.
After worker destruction, the second proof is encoded and independently decoded/
verified, then the original proof is directly verified. Its capture retains the
budget after the source artifact is consumed/deinitialized.

Observed routed worker peak: **1,502,575,254 bytes**, with a 4 GiB test cap and
64 MiB idle scratch retention. This diagnostic measurement excludes the allocations
listed above and is not production sizing guidance. Preparation's tracked peak
remains 1,242,103,479 bytes; its retained charge is now 461,491,887 bytes after the
budget lease counter was added. Proof artifacts remain 111,428 bytes with key
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 remain unchanged. No speed comparison is claimed
from test duration.

Remaining: total multi-job admission (including separate layer/stack allocations)
and actual preparation/proving overlap. Production profile/key integration,
binary/parent-of-parent and Metal qualification remain unfinished. The original
fused PCS/DEEP and final-layout witness goals remain active.

Logs and source snapshots are pinned by relative SHA256SUMS.
