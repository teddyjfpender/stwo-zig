# Deferred unbuilt query-STARK wiring

Status: UNBUILT, UNQUALIFIED. This checkpoint saves an earlier attempt to prove the ALU-only native P2 query graph through the dedicated five-roster CPU prover. The user redirected the stream to full-leaf census, native GPU hash measurements, and capture/setup request measurements before this wiring was tested.

The files are quarantined here so the qualified graph fixture main remains unchanged. query_fixture.zig belongs at src/integrations/riscv_cpu/poseidon2_outer/query_fixture.zig, the harness belongs under scripts/, and graph-main.patch records the optional CLI branches. Do not apply or promote without adapting to the current Context/Authority APIs, building, and running its fresh-process/tamper corpus. No test, proof acceptance, performance or whole-CPU/Ethereum claim is made for this saved work. Existing accepted reference five-roster proofs and actual full-leaf census receipts are separate artifacts.
