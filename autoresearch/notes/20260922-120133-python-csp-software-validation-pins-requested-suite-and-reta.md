---
title: Python CSP software validation pins requested suite and retained verifier transcript
author: Teddy Pender
created_utc: 2026-09-22T12:01:33Z
---

# Python software CSP suite admission — 2026-09-22

Software validation now accepts an explicit requested suite, defaulting to the
existing BLAKE2s behavior. One mapping pins artifact version/exchange mode,
benchmark schema and verifier schema: BLAKE2s v4/v4/riscv_proof_v3/riscv_verify_v1;
BLAKE3 v5/v5/riscv_proof_v4/riscv_verify_v2. Artifact/report/receipt admission
uses the requested mapping instead of independently accepting either family.

Reports and verifier receipts require the suite-appropriate transcript field.
BLAKE3 requires the exact three-field suite/version/digest object, version integer
2 (not bool), lowercase canonical digest, and absence of the legacy field.
Legacy reports reject modern receipt fields. The software runner now compares
the independently verified retained artifact transcript against the benchmark
transcript. Previously it checked proof/statement hashes but omitted this check.
The current runner still requests BLAKE2s until product/CLI suite selection is
implemented; these helpers do not silently change defaults.

Validation command:

```
python3 -m unittest scripts.tests.test_riscv_csp_benchmark scripts.tests.test_riscv_csp_native_isolation scripts.tests.test_riscv_csp_precompile scripts.tests.test_riscv_csp_proof_suites
```

72 tests pass. Added modern report/verifier parity, cross-suite rejection,
wrong artifact/verifier schema, malformed/ambiguous receipts, boolean version,
unknown suite, and valid-but-different verified transcript cases. Existing
receipt fixtures now contain actual producer-required transcript/version fields.
No full software BLAKE3 proof is asserted by synthetic validation fixtures.

Next: product CLI engine selection and runner propagation, including explicit
requested-suite checks on ECDSA precompile/software fallback, then complete
regular v5 proof qualification and full canonical CPU/Metal CSP results.
