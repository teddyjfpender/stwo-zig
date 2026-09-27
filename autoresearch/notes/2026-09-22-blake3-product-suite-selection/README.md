# Product suite selection and ordinary BLAKE3 CLI proof — 2026-09-22

Both product bindings now expose a typed BLAKE3 engine selected through the shared
prefix `--proof-suite blake3 <command> ...`. Default and explicit blake2s retain
legacy behavior. Unknown, incomplete and duplicate prefix selections are rejected.
Metal's ECDSA runtime guard is instantiated for the selected engine. The Python
runner exposes --proof-suite, propagates it through software prove/verify,
precompile commands and proved software fallback, and requires matching artifacts
and receipts. The prefix is before the command, not an arbitrary-position option.

The CPU product built successfully (stwo-zig-riscv-cpu, ReleaseFast; 1 minute,
5 GiB maximum RSS). The complete regular SHA-256/128-byte CSP guest (14,056 cycles)
proved under secure 70-query/26-PoW-bit parameters, emitted JSON artifact v5 and
riscv_prove_v2 with a typed BLAKE3 receipt. Fresh CLI verification emitted
riscv_verify_v2 with an identical receipt. Selecting blake2s for that retained
artifact failed with ProofSuiteMismatch. Tampering proof bytes was rejected.
The bench command also completed with one sample, no warmup, riscv_proof_v4,
modern receipt and no legacy transcript field. Reports and proof are retained.
This dirty-development product is not an admitted clean full-suite benchmark;
its diagnostic timing must not be mixed into the published CSP matrix.

Checks: standalone prefix parser test passes; 72 focused Python CSP tests pass;
CPU product compilation and the prove/verify/bench commands pass. Metal binding
is edited but the Metal product has not yet been compiled/run with this selector.
Earlier authenticated AOT ECDSA harness qualification remains separate evidence.

Build exposed legacy Poseidon guest-profile paths whose ProfileEngine and binary
v1 codec remain BLAKE2s. Those paths now reject a selected BLAKE3 engine instead
of decoding the wrong proof type or silently producing a different suite. That
profile still needs a separate BLAKE3 publication migration; guest-requested
Poseidon operations are not being removed. Archived build failures document this.
An initial mistaken build target was corrected to stwo-zig-riscv-cpu. An initial
verify invocation supplied --input, which the regular verifier correctly rejected
as IrrelevantInputBinding; retry used the existing ELF/statement binding contract.

Commands are captured in blake3-cli-case.json and the logs. Next: compile/run
Metal product selection with the current AOT bundle, strengthen runner propagation
coverage, establish source-pinned clean benchmark products, and run the full
canonical CPU/Metal matrix. Production recursion and prover-owned Poseidon
statement identity migration remain incomplete. No goal completion is claimed.
