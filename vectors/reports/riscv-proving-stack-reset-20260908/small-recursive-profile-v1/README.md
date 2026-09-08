# Small recursive proof attribution

The retained baseline is `phases.log`; `baseline-source.json` pins its source,
binary and log. It completed successfully. The producer and verifier phase
records partition their bodies before deferred cleanup; the receipt timings
include cleanup. Inner STARK verification and publication timings are nested
and must not be added to the whole verification time.

`verifier.sample.txt` samples `sampled-run.log`. That run is perturbed by the
sampler and is attribution evidence, not a throughput baseline.

The fixture executes one RISC-V instruction and proves the real 39-component,
47-domain recursive AIR. Its q1 child and q3 outer proof use development
profiles and no PoW. Verification freshly decodes the artifact after destroying
the outer producer, but still accepts the retained native prepared leaf as
admission input. This is not a detached-key root or production-security
benchmark.

Reproduce from the repository root:

```sh
env -u STWO_RECURSION_OUTER_CLOSURE_DIAGNOSTIC \
  -u STWO_RECURSION_DIAGNOSE_COMPOSITION \
  python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-concrete-outer-proof \
  -Doptimize=ReleaseSafe --summary all
```

`admission-mutations.log` records the frontend cohort/closure mutation gate.
Its scope is structural/protocol mutation coverage; the actual executable is
the independent complete-proof acceptance gate for concrete integration code.

`comparison.json` contains three complete process runs per variant in ABBAAB
order; `paired-runs.json` retains exact executable hashes, commands, exit status,
log hashes and request times. `admission-once.log` is the intermediate envelope
reduction; `boundary-once.log` includes the subsequent boundary and engine
reduction. Their adjacent source receipts identify each build.

Every comparison run has exactly one successful outer receipt, unchanged
39-row/47-domain/one-worker/90,173-byte shape, zero producer live bytes, both
codec rejections, and exact per-run producer/verifier phase sums. Each process
also completes the subsequent existing replay and recording checks. The
comparison does not assert proof-byte identity or stronger profile security.

The original benchmark source is reconstructable from this checkpoint in an
isolated checkout by reverse-applying `baseline-to-final.patch`. Its companion
verification receipt records exact reverse/forward source-hash checks for core,
cohort and engine. The engine reconstruction matches `baseline-source.json`
exactly; the other two baseline files match source base73f6c120. Benchmark
provenance therefore does not depend on keeping a Zig cache binary indefinitely.
