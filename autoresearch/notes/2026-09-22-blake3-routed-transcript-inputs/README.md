# Routed private transcript absorption

Previous turn: progress; the qualification parent contains the native verifier's
transcript, arithmetic and authentication paths. Its preprocessing still depends
on the particular child proof. This stage starts removing that dependency at the
transcript input boundary; it does not claim a reusable parent key.

The transcript compiler adds routed_words and routed_felts operations. They use
existing frame payload provenance and byte-routing AIRs, leaving structural
framing fixed while obtaining payload bytes from external authenticated producers.
Prepared.payload_reads owns an operation-indexed list of caller identities and
exact per-word multiplicities. No payload is silently given an unconstrained
source: callers must supply bounded raw-word or canonical field-byte producers.
Aliases with the entire transcript namespace range are rejected before building.
Existing public words/felts behavior is preserved.

Prepared.final_digest is optional host inspection data, not a new proof output
or root anchor. The complete proof test constrains a subsequent native challenge,
uses bounded private-word rows and a canonical field-byte encoder fed by a private
QM31 source, and reconstructs preprocessing with zero payload placeholders.
The unit test varies every absorbed value, compares all fixed columns, checks
native digest parity, read receipts, namespace aliases and allocation failures.

Remaining fixed-data dependencies found by this audit:

| Boundary | Current source | Required production work |
| --- | --- | --- |
| Absorbed samples/claims | Public felts in full-STARK prefix | Use routed_felts and shared authenticated arithmetic inputs |
| Committed roots | Public root boundary rows | Route authenticated external digest producers |
| Challenge results | Public draw output boundaries | Route to arithmetic consumers with exact multiplicities |
| Rejection attempts/counters | Operation attempts determine schedule | Fixed-capacity constrained attempt selection and counter routing |
| Raw query outputs | Public query boundaries | Shared constrained query consumers |
| Merkle path direction/index | Statement index selects fixed routing | Constrained dynamic routing tied to query bits |
| Merkle roots and leaf values | Public fixture boundaries | Shared transcript/arithmetic/commitment sources |
| PoW nonce | Frame and integer values fixed | Routed nonce with shared PoW and absorption source |
| Arithmetic graph inputs | Per-proof public expected coordinates | Shared private sources and reusable public-input contract |

The full parent fixture is unchanged by this stage and still uses public
absorption operations. The new route must be integrated with those shared
sources; replacing anchors with unrelated private witnesses would be unsound.
Production still uses Poseidon. Production key/profile admission, CPU/Metal,
parent-of-parent qualification and performance evidence remain outstanding.

Validation commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-routed-transcript test-blake3-transcript-sequence -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-routed-transcript -Doptimize=ReleaseSafe --summary all
```

The public transcript regression passed its two tests (4 seconds / 394 MiB,
compilation 22 seconds / 1 GiB). Initial routed-test compilation rejected a runtime
array of types; it is now comptime. The final routed gate passed both tests,
including the complete proof, in 4 seconds / 352 MiB; compilation 24 seconds /
1 GiB. The initial and final logs are retained. Formatting and whitespace checks
passed. The unchanged full parent proof was not rerun, and no broad suite was run.
