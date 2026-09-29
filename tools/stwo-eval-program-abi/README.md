# Evaluation-program ABI

The single source of the backend-neutral evaluation-program ABI that stwo-zig's
AIR recorders emit: the `STP1` program (`program.rs`, `program/build.rs`), its
byte encoding (`encoding.rs`), the `EvalAtRow` recorder (`recording.rs`,
`recording/base.rs`), the semantic differential against the framework's point
evaluator (`semantic.rs`), the proof-dependent-constant classifier
(`parameters.rs`), the two-recording component capture (`capture.rs`), the
`STWZEVA/1` bundle container (`bundle.rs`) and the ABI byte-compare fixture
(`abi_fixture.rs`).

It is compiled into two tools, each against its own Stwo pin:

| Consumer | Stwo | Output |
|---|---|---|
| `tools/stwo-cairo-air-compiler` | `7b211ed` (Stwo-Cairo `82f2125`) | `vectors/cairo/official/*.air_programs_v1.bin` |
| `tools/stwo-circuit-oracle-rs` | `proving@5a7c5ed` | `vectors/circuit/official/circuit_air.air_programs_v1.bin` |

Each consumer includes `src/lib.rs` with
`#[path = "../../stwo-eval-program-abi/src/lib.rs"] mod eval_program_abi;`, so
`stwo` and `stwo_constraint_framework` resolve to the consumer's own pinned
crates. The directory therefore has no `Cargo.toml` or lock and no
dependencies, and neither consumer manifest needs a path dependency or a
`[patch]`. The recorder only drives `FrameworkEval::evaluate`, and
`FrameworkComponent` derefs to its evaluator in both pins, so it needs no
private-field accessor.

Both tools start by encoding the fixture program of `abi_fixture.rs` and
require the committed bytes; the Cairo compiler's committed bundles are
byte-identical to those recorded before the extraction. Provenance covers these
sources: the Cairo AIR compiler's `generator_closure_sha256` hashes this tree
after the compiler's own, and the circuit oracle's `source_sha256` includes it.
