---
title: Canonical BLAKE3 CSP ECDSA verifies on Metal source JIT at 0.903 seconds
author: Teddy Pender
created_utc: 2026-09-22T11:41:59Z
---

# Canonical BLAKE3 CSP ECDSA on Metal source JIT — 2026-09-22

The complete CSP ECDSA guest proof now passes on the BLAKE3 Metal engine with
70 queries, 26 PoW bits, precompile enabled and 16 workers. One ReleaseFast sample:
execution 0.000764458 s, proving 0.902787958 s, independent verification 0.087134666 s,
1,828 cycles, 3,748,258 proof bytes. Transcript suite/version admission, wrong
input, wrong ELF, invalid recovery/scalar inputs and tampered-proof rejection
checks are retained. Test telemetry records 128 Metal dispatches and 5 CPU
fallbacks across the whole test; those counters include negative checks and
must not be presented as an isolated successful-proof profile.

This uses explicitly selected diagnostic source JIT, not authenticated AOT.
It is a single qualification sample, not evidence of a speedup over historical
0.882 s or a controlled comparison with the earlier 0.994 s CPU sample. Source
JIT initialization occurs before csp.proveWithRecorder timing. Stage JSON is
retained in metal-qualification.log.

The CPU CSP proof helper moved into a shared frontend test harness; both backend
instantiations now run the same fixture, security, receipt and negative checks.
The profiler/backend label is supplied explicitly so Metal cannot be reported
as CPU. The new Metal target is separate from authenticated-AOT acceptance.

Command (repository root):

```
STWO_CSP_FIXTURE_ROOT="$PWD/vectors/riscv_csp" STWO_CSP_PROFILE=1 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-csp-ecdsa-jit -Doptimize=ReleaseFast --summary all
```

Terminal result: 3/3 steps, 1/1 full-proof test; run 5 s / 502 MiB maximum RSS;
compile 1 minute / 3 GiB. Test wall time includes negative checks and runtime
setup and differs from successful-proof timing.

Remaining: authenticated AOT qualification, characterization of fallback
categories, full CSP suite on CPU/Metal, captured work receipts, default suite
promotion, production recursion and prover-owned Poseidon statement identities.

The shared-harness CPU regression also passes: serialized ReleaseFast
`test-blake3-csp-ecdsa`, same fixture root, 1/1 guarded proof test (4/4 steps),
2 s test execution / 1 GiB maximum RSS; compile 58 s / 3 GiB. Full log retained.
This regression run had profiling disabled, so it is not a controlled performance
comparison with the profiled Metal qualification.
