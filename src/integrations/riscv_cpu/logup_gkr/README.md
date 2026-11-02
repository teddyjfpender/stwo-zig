# Experimental LS-range LogUp-GKR

This module proves range membership of sixteen committed query columns captured
from LS and LS-tail witnesses. It is a separate mini-AIR and receiver, not the
Word16 execution verifier. It does not prove CPU execution, LS ownership, global
RAM closure, Ethereum output, or a recursive root.

The classic and GKR variants share the same captured query values. The GKR
variant authenticates its terminal multilinear claim using committed eq and
prefix columns, then closes the range lookup against fixed tables. Variant,
geometry and security configuration come from the receiver.

```
zig build test-riscv64-logup-gkr-prototype -Doptimize=ReleaseSafe
zig build test-riscv64-logup-gkr-prototype -Doptimize=ReleaseFast
zig build rv64-logup-gkr-prototype -Doptimize=ReleaseFast
zig-out/bin/rv64-logup-gkr-prototype capture REQUEST JOBS OUT.witness
zig-out/bin/rv64-logup-gkr-prototype produce classic OUT.witness CLASSIC_DIR
zig-out/bin/rv64-logup-gkr-prototype produce gkr OUT.witness GKR_DIR fast 6
zig-out/bin/rv64-logup-gkr-prototype verify gkr GKR_DIR/proof.bin 20 18
```

The example receiver logs must match the independently selected workload.
`reference` selects the existing generic GKR prover; `fast` selects the
clone-free implementation. Their encoded proofs must match for the same input.

The standalone prototype's private pool defaults to one helper and accepts
1–64 helpers explicitly. It is not coordinated with the execution prover's
worker budget. Input filling also uses bounded temporary threads; these phases
finish before GKR's pool starts. The caller must budget concurrent invocations.
Both GKR implementations still materialize input/layer tables, so fewer
committed interaction cells do not establish lower peak memory or faster
end-to-end proving.

The dedicated suite includes committed-column binding attacks, malformed GKR
messages, receiver statement/variant mismatches, mixed-size generic/singles
transcript parity and worker/input admission cleanup. Exhaustive allocation
failure qualification, production integration, independent protocol review and
recursive-verifier integration remain future work. The design is in
`design/riscv-proving-stack/rv64-logup-gkr-prototype.md`.
