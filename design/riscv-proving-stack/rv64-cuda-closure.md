# Resident local and global closure

`gkr.enqueueWithClosure` adds the native whole-local rational-sum gate to the
previously qualified mixed-height GPU traversal. Its verdict allocation is
generation-, range- and alias-checked alongside the complete workspace and
inputs before the first enqueue. The GPU checks the packed root claims on the
same lane. No transcript draws or native proof fields change. The returned
`ClosureEnqueued.validate` requires both a zero joined verdict and the completed
native traversal header. The raw `enqueue` remains available for numerical
fixtures whose lookup sums are deliberately unclosed.

For roots `(n_i,d_i)`, the kernel rejects noncanonical coordinates and every
`d_i=0`, including `0/0`. It folds projectively:

```
N' = N*d_i + n_i*D
D' = D*d_i
```

Starting from `(0,1)`, the final numerator must be zero. This is the same
condition as native `closure.closeFor`, with direct field pole checks instead
of the inverse hints needed by its circuit form. Each local challenge namespace
is already separated by the native tuple/challenge authority; this closes the
joint whole-local sum, not one independently invented sum per namespace.

The separate execution claim kernel accepts one `(RAM,KIO,Wire)` triple and a
relation-presence bitmask per worker. Three block reductions preserve the
independent namespace sums. They also reject nonzero claims for absent
relations, malformed masks and noncanonical fields. Thus balanced absent claims
cannot evade the check, and RAM cannot cancel KIO or Wire. The worker cap is the
native manifest's 65,535; the local cap is the GKR controller's 64 instances.
Both operations preserve pre-existing sticky error flags.

These are arithmetic closure gates. They do not authenticate their inputs.
Execution acceptance still requires the complete receiver-owned roster,
independent statement/MAIN/FIXED root binding, every physical proof, and the
native transcript binding of the corresponding claims. The current GPU route
has not yet produced an accepting complete Stark/Ethereum proof.

## Evidence

The cold fixture tool invokes the existing native `LocalClosure.close` and
`PendingManifest.checkGlobalClosure`. Fifteen native cases cover counts 1,
2, 3 and 64 for local roots and 1, 2, 18 and 65,535 for global workers, including
zero-weight poles, unclosed sums, cross-relation cancellation, balanced absent
claims and sticky status. Four extra framing mutations reject noncanonical
roots/claims, invalid masks and zero denominators. Native pointer/capacity/context
guards are exercised before enqueue.

The connected full-GKR harness now checks root closure as well as every native
proof record, mask, challenge, terminal marginal, binding metadata, Eq and
prefix witness. Eight pre-existing fixtures remain byte-identical; a ninth
adds nonzero cancelling numerator pairs. Both closed cases pass the root gate;
unclosed numerical fixtures are identified as such instead of being relabeled
as accepting lookups. The harness covers 178 binding metadata/witness cases,
nine traversal poison cases and eleven binding poison cases.

Both drivers pass normally and under memcheck, racecheck, initcheck and
synccheck on the RTX 5090. Native fixture export, hardware qualification and
source/fixture/object/executable hashes are reproducible through:

```
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-closure-fixtures -Doptimize=ReleaseSafe -- /tmp/rv64-closure-fixtures
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-gkr-fixtures -Doptimize=ReleaseSafe -- /tmp/rv64-gkr-closure-fixtures
```

`scripts/rv64_cuda_closure_qualify.py` runs both drivers and all four sanitizers
with the qualified dependency objects. Receipts are in
`vectors/reports/rv64-cuda-closure-20261103/`. Host integration tests pass 69/69
in ReleaseSafe and ReleaseFast; the real FFI also compiles in both modes. No
new block timing is claimed.
