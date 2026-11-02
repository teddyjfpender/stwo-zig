# Final PR309 CPU handoff

Pinned full block24,628,607:104,253,913 instructions,25 CPU and5 truth proofs, no recursion.

Final combined source85d93b080: **292.261s proving**, **331.38s process wall**, **39.999GB peak RSS**. All33 authoritative artifacts match the prior same-profile/geometry run; the old separately frozen receiver accepts the complete block. The final combined observation is slower than the earlier286.008s packed-FRI observation; no additional holistic gain from the last two kernel slices is claimed. Unchanged controls were305.846s and314.144s.

The stronger beta2/q256/P0/fold4 candidate remains `security_qualified=false`. The executable source-derived conditional security calculation is recorded in `security-model.json`; it is not an unrestricted whole-protocol128 certificate. The later Linux-only integer-coercion correction does not change macOS proof execution or parameters.

See [handoff](../../../design/riscv-proving-stack/rv64-pr309-guest-gpu-handoff.md), the full run receipt and logs, combined build log, per-slice Safe/Fast qualification, source-binding check and CI observations. GPU execution and guest merge are deferred.
