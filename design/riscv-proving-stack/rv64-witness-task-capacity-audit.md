# Witness task capacity audit

Production task registration keeps geometric ArrayList growth. Reserving every
origin/gate/variable would count seeded constants, in-place constraints and
padding that registration skips. Exact accepted task counts depend on producer
coverage, multi-output gates and the existing duplicate/missing checks. A count
pass has a real cost and cannot be treated as free.

The isolated audit adds optional growth census fields. It starts a clock only
when metrics were requested and append needs capacity. Moved bytes count the
previous live Task bytes only when the backing pointer actually changes. It
also includes a test-only exact-capacity oracle; production does not call it.

The benchmark builds original finalized QM31 circuits with chained BlakeG and
QM31 arithmetic. All constraints validate, replay exactly matches builder
values, and ordinary/oracle tasks, seeds and levels match exactly. These are
constructed representative graphs, not captured production leaf/fold graphs.
The tracking allocator deliberately refuses remap/resize; measured requested
live-byte peaks exclude the graph, other reference plans and recycler idle
blocks. Thus these are neither production allocator nor Xeon measurements.

| Variables | Accepted tasks | Growth moves | Copied bytes | Growth time | Whole plan | Free-oracle plan |
|---:|---:|---:|---:|---:|---:|---:|
|150,270|75,260|21|2,349,360|0.146ms|2.272ms|2.107ms|
|1,500,270|750,260|27|26,814,672|1.510ms|22.716ms|21.119ms|

These are medians of six samples per graph across two test executables. The
largest ordinary task capacity is1,117,538 versus750,260 accepted tasks. The
free oracle lowers the measured plan requested-live peak from49,001,636 to
44,594,300 bytes. Its count comes from a previously validated plan and is not
available free in production. An extra count/validation pass could erase the
roughly1.6ms whole-plan difference.

Keep production growth unchanged. The next evidence needed is census from
actual CPU/Keccak/fold graphs on the production bounded recycler. Do not
extrapolate this graph mix to the492ms production task stage or claim a
production speedup/memory reduction. The compact JSON receipt preserves all
samples and qualification scope; no GPU budget was used.
