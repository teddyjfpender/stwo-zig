The prover now borrows caller N/D, moves consumed upper layers into sumcheck,
and borrows one immutable Eq table within each enclosing GKR layer. The caller
inputs survive unchanged for subsequent PCS binding. Existing clone APIs retain
their independent-copy contract; the new owned sumcheck API consumes its array
and elements on every exit, including malformed-input and allocation failures.

| row log ×16 terms | before peak | after peak | caller input bytes |
|---|---:|---:|---:|
|14|71,332,576|26,217,704|9,437,184|
|16|285,248,368|104,861,016|37,748,736|

These are requested live allocator bytes (−63.2%), not RSS. They include caller
N/D, tree, Eq, live oracles, proof/artifact; they exclude production MAIN,
post-GKR binding witness, PCS, recursion and allocator overhead. Both before/after
runs have identical proof hashes and transcript digests, fresh terminal binding,
unchanged caller matrices and zero final live bytes. No throughput claim.

For a single M31-numerator/OM31-denominator matrix with n facts, caller input is
36n bytes and the upper secure pair tree is 64(n−1). The observed dominant peak is
100n plus a few KiB of metadata/proof. This is not a complete admission bound for
mixed heights/instances. Do not replace the hard allocator or lower admission on
this observation. The previous 136B/fact plan is not an upper bound for the old
implementation (actual ~272B/fact). A complete bound must account all headers,
proof/masks, Eq generation and overlapping fold buffers for each instance.

Reproduce (repository root):

```
zig test -OReleaseSafe --dep stwo_core -Mroot=src/prover/lookups/owner_memory_test.zig -Mstwo_core=src/core/mod.zig
zig test -OReleaseFast --dep stwo_core -Mroot=src/prover/lookups/owner_memory_test.zig -Mstwo_core=src/core/mod.zig
zig build-exe -OReleaseFast --dep stwo_core -Mroot=src/prover/gkr_memory_probe_root.zig -Mstwo_core=src/core/mod.zig -femit-bin=/tmp/gkr-memory
/tmp/gkr-memory 14
/tmp/gkr-memory 16
```

The baseline binary was compiled on base eddd33db8 with the same probe added
before the ownership source edits. Baseline reproducibility requires applying
only the two probe files to that base. All measurements used a shared host.
The existing historical real-Q LS20/tail18 capture was reproved after the final
build and is byte-identical to its committed fixture; the fresh receiver accepts.
