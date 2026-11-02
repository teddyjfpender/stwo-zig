# Balanced retained-projection corruption

This test-only fixture retains the same committed ALU MAIN, numerical GKR proof,
terminal claims and eta. It changes two physical projected cache rows by
`delta(P0) = Eq1` and `delta(P1) = -Eq0`. Their Eq-weighted changes cancel exactly.
Finalizing the corrupted cache therefore succeeds and preserves the last cyclic
prefix value; the complete Eq/prefix witness nevertheless differs.

The physical prover's existing diagnosed failure-retention API exposes the invalid
proof at its final OODS check. A separate, freshly initialized physical receiver
must reject that proof. An early producer error alone cannot satisfy this case.
This extends the actual ALU fragment binding qualification; it does not claim a
standalone fragment is an accepting complete-execution receiver.

Reproduce with:

```
zig build test-riscv64-services-gkr-local -Doptimize=ReleaseSafe -Driscv-test-filter="balanced projected cache" -j2 --summary all
zig build test-riscv64-services-gkr-local -Doptimize=ReleaseFast -Driscv-test-filter="balanced projected cache" -j2 --summary all
```

Both commands are run under the shared heavy-work lock. The filtered suite guard
requires an executed test matching the name. The log records the exact fresh
receiver rejection. Production source, protocol, statements and defaults are
unchanged.
