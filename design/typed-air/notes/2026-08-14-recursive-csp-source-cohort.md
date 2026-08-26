# Recursive CSP source-cohort authority

Status: implemented benchmark admission rule; no comparative result published.

## Decision

The canonical recursive CSP producer admits a benchmark request only when all
of the following are true:

1. the native measurement commit is the exact implementation commit embedded
   in the recursive producer;
2. the recursive producer was built from a clean tree;
3. the guest, input, output, and execution-cycle identities match the sealed
   canonical CSP manifest and native row; and
4. the newly derived public-values diagnostic is byte-for-byte identical to
   the native row's pinned public-values diagnostic; and
5. the native report is schema v4 evidence whose run, every measurement row,
   and summary all attest `recursion_enabled=false`.

The retained native statement digest remains explicit context in every
request and successful attempt. It is not silently rewritten to make an old
cohort appear comparable.

This rule intentionally makes historical native reports contextual baselines.
They remain useful for understanding prior prover behavior, but they cannot be
paired with a recursive artifact built from a different source statement. A
comparative cohort must first recapture the native prover on the same clean
implementation commit, then use that sealed report to drive the recursive
collector.

The v4 boundary is intentionally not inferred for retained v2/v3 reports.
Those reports predate the isolation attestation and cannot enter a recursive
measurement plan even if their timings remain useful historical context.

## Native recursion-isolation contract

The ordinary product benchmark emits `riscv_proof_v3`. Before it can emit
`recursion_enabled=false`, the adapter walks the complete hierarchical prover
stage tree and rejects any recursive, outer, or pair-node stage at any depth.
The ordinary product adapter calls the no-execution-policy prove API; API
reflection pins that the ordinary overloads accept no `ExecutionOptions`, and
the default value has neither a CPU execution request nor a statement-admission
callback. The standard `riscv-csp-bench` build step depends on the native CPU
product and trace diagnostic only, never the recursive producer.

The Python harness additionally removes the complete `STWO_RECURSION_*`
namespace from every prover and retained-verifier child environment. It records
the removed variable names, never their values. Any missing/true product
attestation or any recursive/unauthenticated row aborts before report
publication. The outer report is `stwo_riscv_csp_benchmark_v4` and repeats the
false attestation at run, row, and summary scope.

The active `stwo-perf` RISC-V board consumes the same exact
`riscv_proof_v3` envelope and rejects a missing or true attestation. Historical
`riscv_proof_v2` evidence retains its original label and remains readable as
history, but it is neither relabelled nor admitted to a new paired run. The
manifest, runner, schema documentation, and generated track briefs migrate as
one contract; the provenance-bound site feed is regenerated only from the
eventual clean committed source state.

## Why commit equality is checked before execution

RISC-V public values bind the implementation commit and dirty bit. Waiting for
the public-values SHA-256 check would still reject a stale cohort correctly,
but only after guest execution. Request schema v3 therefore carries the native
measurement commit and the producer checks it at `source_admission`, before it
loads or executes the guest. The later public-values equality remains the
stronger statement-level check and is not removed.

Dirty recursive binaries are diagnostic development products, not comparison
authorities. The producer rejects them instead of overriding embedded
provenance, relabeling a historical statement, or manufacturing a matching
digest.

Schema v3 additionally carries the exact bounded recursion-profile name, its
shape seal, and the registry seal. Shape selection is rebuilt from production
statement geometry before native proof construction. See the
[canonical profile registry note](2026-08-14-recursive-csp-profile-registry.md).

## Evidence boundary

The current retained artifact is an independently verified canonical
outer-child wire for the active 36-row verifier subsystem. It is explicitly
classified as comparison-ineligible until a complete recursive parent proof is
production-active. Even after that protocol boundary closes, no old-versus-new
ratio is available until a fresh same-source native cohort satisfies the four
admission checks above.

The benchmark sequence is therefore:

1. commit the candidate source and require a clean tree;
2. build the native prover, trace diagnostic, and recursive producer in
   `ReleaseFast` from that commit;
3. capture and validate a fresh native CSP cohort;
4. seal a recursion plan from that exact native report;
5. collect recursive attempts with the same manifest, workload identities,
   warmups, sample counts, host policy, and worker policy; and
6. publish a comparison only after both the full recursive proof boundary and
   the paired source/statement identity boundary validate.

The historical reports stay in the evidence archive and may be rendered as
context, but never enter a paired speedup denominator.

The controlled command sequence is:

```sh
zig build stwo-zig-riscv-cpu riscv-trace-dump \
  riscv-recursion-csp-producer riscv-recursion-shape-inspector \
  -Doptimize=ReleaseFast
python3 scripts/riscv_csp_benchmark.py \
  --backend cpu \
  --cli zig-out/bin/stwo-zig-riscv-cpu \
  --trace-cli zig-out/bin/riscv-trace-dump \
  --report-out zig-out/riscv-csp-current-native.json
python3 scripts/riscv_recursion_csp_benchmark.py plan \
  --native-report zig-out/riscv-csp-current-native.json \
  --output zig-out/riscv-recursion-current.plan.json
python3 scripts/riscv_recursion_csp_benchmark.py collect-canonical-outer \
  --plan zig-out/riscv-recursion-current.plan.json \
  --workers 8 \
  --artifact-directory zig-out/riscv-recursion-current-artifacts \
  --output zig-out/riscv-recursion-current.json
```

Every output path must be new. The first two commands require a clean committed
tree; the collector remains deliberately blocked while any canonical profile
is catalogued but not outer-wired or while full parent proof production is
unavailable. No partial subsystem timings are promoted into a speedup ratio.
