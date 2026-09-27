# Persistent BLAKE3 commitment PCS columns

The admitted program/memory component emitter now writes into final PCS columns.
The heap-stable owner retains independent preprocessing, typed definitions,
authenticated relation plans and main buffers. Canonical bit-reversed placement
uses the existing framework writer. Column views combine main and fixed columns
directly, without a retained logical-row/metadata copy.

Lookup registration, framework interaction generation with reusable inversion
workspaces, and prover/verifier component binding consume those views. A failed
witness re-admission invalidates main/prover access until a complete retry.
Component claims do not by themselves close execution or lookup-table relations;
complete proof orchestration and complete PCS key/artifact admission are pending.

ReleaseSafe test-riscv-statement-codecs passes (45 s, 2 GiB): all emitted logical
rows match final-column reads; padding is zero; lookup registration succeeds;
main/interaction columns and typed prover/verifier adapters are constructed;
the memory interaction claim and full storage match the existing row generator.
A changed program multiplicity rejects, invalidates stale views, and a valid
retry reuses the same main buffer. This is engine-interface qualification,
not a complete RISC-V STARK or an end-to-end speed measurement.
