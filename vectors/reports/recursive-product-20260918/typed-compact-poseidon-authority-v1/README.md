# Typed compact-Poseidon admission authority

`air/lang/typed_poseidon2_compact.zig` lowers the existing canonical typed width-16 Poseidon permutation into the admitted compact physical AIR. It derives the 142 square/fifth-power cuts from the typed graph, producing 284 materialized columns, 303 total columns, 288 ordered direct constraints, and four ordered lookup events. It contains no copied round constants, round schedule, or matrix implementation. The layout constants have one independent owner.

Compact provider admission now constructs this typed definition and authenticates every direct polynomial, lookup domain/role/arity/numerator/tuple, and both LogUp interaction recurrences against the executable specialization. Both recursive producer and standalone verifier use this admission boundary. Specialized native evaluation and witness generation remain available; they do not acquire an independent semantic authority. The typed authority has no prover or witness dependency.

## Identity and compatibility

Typed IR interns commutative operands by node ID. The first exact-structure experiment therefore differed from the existing ordered protocol digest despite numeric equivalence. The final implementation keeps the original ordered protocol digest unchanged and uses a separately domain-separated equivalence digest permitting only addition/multiplication operand swaps. Subtraction order, grouping, input positions and all event metadata remain significant. Tests reject mutated specialization constraints, lookup numerators/order and interaction equations. No manifest or identity pin was regenerated to accommodate the mismatch.

The canonical identity remains `e37c589fabffa3711c41c6cb259e68303543bc36edcef3d5be5caec7459f8ddf`. Source provenance includes the typed lowering and geometry owner independently.

## Validation

- `test-compact-poseidon-authority`: 127 passed; 8-second compile and subsecond execution on the qualification run. Covers base/extension off-trace differentials, all provider modes, padding, all 284 materialized-column mutations, degree three, symbolic equivalence, normalization boundaries and partial-allocation cleanup.
- `test-parent-canonical-admission`: 228 passed, one skipped. Counts overlap with the compact target; they are separate executions, not unique-test totals.
- Product source closure: 32 passed. Test inventory: two passed.
- Fresh CPU and Metal/AOT four-segment products: 384 checks. Producer exit, standalone serialized verification, malformed proof rejection and same-geometry substitution passed. All 21 proof/key/claim artifacts are byte-identical across backends and to the canonical baseline. Required Metal dispatch assertions passed.

Initial failure logs are retained as diagnostics and are superseded by `pr198-compact-typed-authority-final.log`. `qualified-source-snapshot.json` is shared by both complete-proof runs.

## Canonical complete-proof command

The CLI still defaulted to an old admission with the retired compact-Poseidon source digest. After both gates finished, its default was changed to the exact canonical admission explicitly used in these passing runs. The substitution fixture remains independently pinned. All 14 referenced key/statement files and both default admission digests were verified; no proof rebuild was needed for this argument-default-only correction.

```
python3 scripts/riscv_recursive_product.py --backend cpu --output /tmp/NEW_CPU_OUTPUT
python3 scripts/riscv_recursive_product.py --backend metal --output /tmp/NEW_METAL_OUTPUT
```

Output paths must not already exist. The explicit admission override remains available. `default-admission-check.json` and `post-gate-command-default.json` record the post-gate change. Documentation was appended after evidence capture.

## Remaining work

This closes typed compact-Poseidon admission, not the entire RISC-V cleanup. The leaf executable still imports the legacy outer-proof test harness and selects its old route for no arguments. Separate the canonical detached runner and required workload helpers, remove competing public routes/exports under the complete-proof gate, and then perform final useful continuation qualification. Production security qualification and speed/autoresearch remain separate work.
