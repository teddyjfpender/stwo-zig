# Native query-fusion admission regressions

The production wrapper still validates the owned DEEP evaluation before calling a
private graph-view kernel. A small authenticated 17-node graph exercises that same
kernel without constructing a full proof. The test accepts the exact contraction,
then rejects mutations of every field of all four scalar producers and every field
of the replaced dot4, missing scalar/opening rows, duplicate scalar/opening rows.
An unrelated scalar row is retained exactly. Existing matcher tests cover shared
and exported inputs, and existing AIR tests cover equation and lookup closure.

Focused ReleaseSafe test-recursive-fused-pcs-opening: exit 0, 4/4 steps, 8/8 tests;
run 880 ms / 2 MiB, compile 5 s / 556 MiB. No full proof was needed for the test-only
fixture; the private-kernel extraction is additionally exercised by the subsequent
full native row-staging gate. Production admission remains in the owned wrapper.
