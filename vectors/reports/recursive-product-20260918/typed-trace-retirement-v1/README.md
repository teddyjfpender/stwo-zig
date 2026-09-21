# Typed opcode production boundary cleanup

The production trace owner no longer imports independent retired opcode evaluators. Its eight admission/witness tests and helpers moved to `runner/trace_test.zig`, rooted by both the existing runner/inventory roots and the new focused `test-trace-authority` target. BASE_ALU_IMM and BASE_ALU_REG oracle files now use explicit `_legacy_test_oracle` names. The production semantics namespace exports shared primitives only; its transitional BASE_ALU_IMM export was removed.

The new source-closure guard walks production trace, constraint-program, and semantics roots (204 files), rejecting retired evaluators, frontend test files, and family-specific semantics implementations. Shared access/shift primitives remain permitted. Independent oracle equations were retained unchanged for differential testing.

Validation:

- `python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-trace-authority -Doptimize=ReleaseSafe --summary all`: 156/156 tests passed; compile 13 seconds, test execution 910 ms.
- `python3 -m unittest scripts.tests.test_product_closure`: 32/32 passed.

No complete-proof gate was run for this test isolation/export cleanup. This does not establish that all frontend providers are typed or retire the recursive legacy routes.

## Next recursion retirement boundary

`detached_parent_contract_v1.zig` admits historical multiplication AIR and wide Poseidon AIR in addition to the current catalog. Both producer and verifier component owners carry corresponding branches. Separately, compact Poseidon accepts a reviewed old source digest for the same canonical equations (`poseidon2_universal_identity_v2.zig`). These are distinct compatibility obligations: deleting alternative AIR requires migrating retained admissions/proofs; removing a source-identity alias requires a deliberate admission migration. Current complete-proof inputs must be inspected before either cutover. Retire replaced outer/temporal routes under the pinned complete-proof gate after any unique required capabilities are covered by detached recursion.
