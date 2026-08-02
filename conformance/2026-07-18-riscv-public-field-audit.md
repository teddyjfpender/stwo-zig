# RISC-V public-field constraint coverage audit

Public-statement closure evidence for
`soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md`.
For every field of `PublicData`, this table names the mechanism that binds it
beyond transcript mixing (every field is Fiat-Shamir-mixed by
`PublicData.mixInto` in the pinned oracle's order — mixing alone proves
nothing about the trace and is not accepted as coverage below).

| Field | Bus / constraint binding | Status |
| --- | --- | --- |
| `initial_pc` | registers-state boundary emit at clock 1; consumed by the first executed row's state-chain pair | BOUND |
| `final_pc` | registers-state boundary consume at clock+1; emitted by the last executed row | BOUND |
| `clock` | closes the state-chain telescope (boundary consume clock); statement consistency check ties it to `total_steps` | BOUND |
| `initial_regs[0..32]` | memory-access boundary emits every register's clock-0 word; first access-site consume must match | BOUND |
| `final_regs[0..32]` | memory-access boundary consumes every register at its final clock; last access-site emit must match | BOUND |
| `reg_last_clock[0..32]` | the boundary consume clock; a wrong clock breaks pairing with the last access-site emission | BOUND |
| `program_root` | checked against the decoded-program sparse tree; committed program leaves and Merkle nodes consume the public root emission, and every parent is coupled to an active Poseidon2 call | BOUND |
| `initial_rw_root` | checked against the initial RW-memory sparse tree; committed boundary leaves and Merkle/Poseidon rows consume the public root emission | BOUND when the oracle-shared optional tree is present |
| `final_rw_root` | checked against the final RW-memory sparse tree; committed boundary leaves and Merkle/Poseidon rows consume the public root emission | BOUND when the oracle-shared optional tree is present |
| `io_entries.input_start`, `input_len` | checked word-index multiplication and address addition over the shared non-wrapping subset; exact word count and canonical final-word padding | BOUND through input_words emissions |
| `io_entries.input_words` | memory-access boundary emits each word at clock 0; the guest's first reads must consume them | BOUND |
| `io_entries.output_len_addr`, `output_data_addr`, `output_len` | classify the public-output words the private final table excludes | BOUND through output_words consumption |
| `io_entries.output_words` | memory-access boundary consumes each word at its recorded final clock; the guest's last writes must emit them | BOUND |

Known envelope limits (not defects, oracle-shared):

- Guests writing input-region words beyond the provided input are outside the
  pinned oracle's supported envelope (its `include_initial = !is_input` rule
  leaves such words publicly unowned). The Zig port matches the oracle
  exactly rather than diverging the transcript.
- Initial and final RW roots are optional exactly when their corresponding
  oracle tree is absent. Presence is semantic: a present zero root emits a
  Merkle tuple and is distinct from absence. The program root is mandatory.

Verified by: the per-domain independence test in `air/public_logup.zig`, the
Merkle leaf/node/hash/root cancellation and mutation tests in
`air/memory_commitment/merkle_node.zig`, boundary-tree validation in
`air/memory_commitment/boundary.zig`, the production e2e prove/verify
roundtrip, and the global relation-cancellation check in
`verifyRiscVWithEngine`. The nine-byte partial-word production proof in
`tests/riscv/public_relation_binding_test.zig` covers nonempty input and
canonical final-word padding. The release oracle additionally compares that
fixture's complete public data, 27 component prefixes, 12 relation-domain sums,
and tuple streams with the pinned Rust implementation. The committed-witness
matrix in `tests/riscv/main_witness_rejection_test.zig` distinguishes an absent
RW root from a present default root in production verification.
