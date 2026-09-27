# Regular BLAKE3 producer and report integration — 2026-09-22

The regular producer serializes proofs with Engine.Hasher, uses the canonical
channel receipt on proving and in-process verification, and emits envelope v5
for BLAKE3. It retains v4 output for BLAKE2s. The BLAKE3 prove report selects
riscv_prove_v2 (profiled: riscv_profiled_prove_attempt_v3) and carries a typed
transcript_receipt, never a BLAKE2s-labelled digest. Legacy report fields and
receipt bytes are retained.

Benchmark report parsing now admits exactly one transcript representation for
the expected suite. BLAKE3 requires suite blake3/version 2 and canonical 64-digit
lowercase hex; mixed legacy/modern fields, wrong suites/versions and uppercase
encoding are rejected. Aggregation selects the expectation from the engine and
emits riscv_proof_v4 for unprofiled BLAKE3, or distinct BLAKE3 profiled schemas.
Null optional receipt fields are omitted by the existing JSON serialization
policy, preserving tested legacy field sets.

Validation: focused adapter report selection passes 9/9 tests. Existing exact
legacy prove and benchmark field-set tests pass, plus new BLAKE3 sample-receipt
validation and ambiguous-field rejection. The standalone report transcript test
also passes. These are report/encoding tests; the BLAKE3 runProve/runBenchmark
instantiations still need complete product execution qualification.

The initial root build used test-riscv-cpu-product with -Driscv-test-filter=report
and ReleaseSafe; a new struct field had a semicolon instead of comma. After
fixing it, replayed only the adapter's exact compiler invocation from the build
log (adapter-command.json, excluding IPC --listen) to keep the development loop
small. A synthetic test then had the wrong expected implementation identity;
fixed it to match its fixture. Both failures are archived. The final replay
passes 9/9; the broader root product step is not claimed green.

Next: explicit suite selection in both products and the Python runner; migrate
Python software artifact/report/receipt admission; compile/run complete v5
regular proofs and tamper checks, then full canonical CSP CPU/Metal results.
No product default promotion or performance claim follows from these tests.
