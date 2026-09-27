# Canonical two-event RAM production route

Source integration is complete. Parent qualification generated the actual
production Driver, Global, Store and MemoryPlan bodies without calling them;
17 of 18 nonproving checks passed. The remaining sorted replay fixture used
reserved access clocks4/8. Its source now derives clocks with the shared
access-clock encoder and retains strict admission. A fresh nonproving check
of that correction and early phase-budget checks is pending. The independent
lane lifecycle root passed7/7. No lane STARK, driver or segment was run by
these checks. Segment proving and block runs remain stopped.

`block_v5_sorted_memory_v1.Pins` is the sole sorted-memory authority: mode0
requires its `word` tag, while mode1 requires `lanes`. The global receiver,
memory join and independent bundle policy reject a protocol/mode mismatch.
The lane receiver freshly verifies the actual lane STARKs, range providers,
initial source and final RW endpoints before exporting common memory buses.
No old word proof receipt or virtual commitment domain is constructed.

The count-first planner uses `ceil(events/2)` physical rows and exact
non-power-of-two instance counts. Each claim binds the real `row_log`, event
count, first/last/preceding transition and global event ordinal. Odd tails
leave lane1 inactive. Limits on instance count, every trace's owned bytes, fixed bytes and
interaction column bytes plus scratch are checked before PCS collection. Collection retains claims, roots, exact
counters and range plans; replay keeps one owned trace and its warm first
round alive at a time and checks the immutable sorted run through exact EOF.
Trace leases borrow collected claims, which must outlive those leases.

The stopped block's recorded census was 356,303,914 accesses: 298,427,187
register accesses and 57,876,727 RW accesses. Canonical mode1 closes registers
through native windows and sends only RW accesses to sorted RAM. At physical
rowlog22, capacity is 8,388,608 events per lane instance, so this RW census
requires seven lane instances versus fourteen one-event word instances. The
43-versus-85 comparison for all 356,303,914 accesses is an abstract all-RAM
geometry example, not the canonical RW plan. Lane instances are wider at the
same physical row cap; fewer instances alone establishes neither lower peak
memory nor a proportional speed improvement.

The lane plan digest includes the new protocol ABI, real row geometry, exact
pins/counters and range roots under B5SS. Transport family16 uses specialized
`B5RAM2A1` artifacts. Decode admits independently supplied pin, configuration,
source seal, roots and column geometry before allocating received proof
vectors. Receiver policy metadata version2 carries the explicit memory tag.
An empty RW plan has no memory or range proof; fresh source/endpoint closure
and the enclosing authenticated RW absence remain mandatory.

`BlockProducer.MemoryPlan{config,plan_digest}` provides native-only admission
without depending on a particular memory artifact type. Its compatibility
wrapper forwards fields from a real collected word artifact. The canonical
driver dispatches the actual lane stage through the bounded proof store, with
no extra segment replay or placeholder artifact.

The source-only nonproving root is
`src/frontends/riscv/block_v5_ram_lanes_production_unit_test_root.zig`.
Filters `block-v5 RAM production` and `block-v5 RAM lane replay sizes` cover
real sorted-run replay, odd tails, EOF/ordinal ownership, preallocation limits,
tagged custody/absence correspondence, register-space rejection, security and
legacy-artifact rejection, and function-address retention of actual planner,
driver, Store, policy and fresh-consumer bodies. No prover, verifier, driver,
CLI, guest segment or benchmark is called by these fixtures. The lane AIR,
proof, receiver and artifact have their own nonproving root owned by the lane
implementation agent. Existing scoped word fixtures use an explicit `fromWord`
constructor; that constructor grants no exception to canonical mode1 admission.
