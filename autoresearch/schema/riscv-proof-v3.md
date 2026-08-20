# RISC-V proof benchmark report v3

`riscv_proof_v3` is the fail-closed benchmark report consumed by the active
RISC-V `stwo-perf` workload group. It extends
[`riscv_proof_v2`](riscv-proof-v2.md) with one required exact field:

```json
{
  "recursion_enabled": false
}
```

The producer may publish this value only after walking the complete
hierarchical stage profile for every warmup and measured sample and rejecting
any recursive, outer, or pair-node stage. The ordinary product adapter uses
the public prove overload that accepts no execution policy; its default
execution options contain no statement-admission callback. Thus `false` is a
checked native-leaf execution boundary, not a caller-provided label.

Missing, non-Boolean, or `true` values fail admission. The report field set is
exact, so a v2 report also fails rather than being silently upgraded. Retained
v2 evidence remains valid under its original historical contract, but it
cannot enter a v3 paired measurement or a recursion-comparison denominator.

All v2 statement, transcript, artifact-v4, resource-telemetry, release-state,
and independent verification requirements remain unchanged.
