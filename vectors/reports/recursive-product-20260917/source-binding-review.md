# Poseidon/table binding review

The seven changed bindings in `scripts/riscv_poseidon_table_uniqueness.py`
were reviewed against the last source revision matching each previous digest.
This refresh retains the existing row-local theorem and exhaustive table
semantic digests. It does not certify recursive soundness, the experimental
q193 profile, the new externalized Merkle shell, or GPU producer integration.

| Source | Previous matching revision | Reviewed change |
| --- | --- | --- |
| `core/fields/m31.zig` | `4c8d79d18b2344e8a6e3ef66049782d22938df55` | Shorter inversion addition chain; exponent remains `2^31 - 3`. |
| `air/memory_commitment/poseidon2_air.zig` | `c11cf4b304b2afe72e3cf17ecafc2b0ab658593c` | Base-field narrow row-pair specialization, generic permutation exports and parity tests; existing constraint schedule unchanged. |
| `air/memory_commitment/hash_component.zig` | `73beeaaa6` | Adds a separate externalized-provider Merkle shell and backend capability. Existing Poseidon constraints remain; the new shell is outside this theorem. |
| `air/lookups/tables/interaction.zig` | `c11cf4b304b2afe72e3cf17ecafc2b0ab658593c` | Shares generic relation entry construction, combines base tuples without promotion, and changes writer chunking. Domain, arity, tuple order, negative multiplicity and singleton LogUp transition are preserved. The prepared evaluator also restores the public `InvalidTraceShape` contract for malformed tuples. |
| `air/lookups/tables/component.zig` | `c11cf4b304b2afe72e3cf17ecafc2b0ab658593c` | Backend capability and prepared evaluator use the same relation with base-field tuples. |
| `air/lookups/entry.zig` | `c11cf4b304b2afe72e3cf17ecafc2b0ab658593c` | Exports canonical `(z, alpha^0, ...)` relation parameters; existing denominator rules unchanged. |
| `prover/preprocessed.zig` | `f3277d521c00b253809f3873355a2764ec57bf97` | Optional phase timing only. |

Frontend paths in the table are relative to `src/frontends/riscv`; the field
path is relative to `src`. The table-entry semantic anchors now bind both the
native-to-generic delegation and its field promotion, domain, sign, arity and
tuple copy, instead of requiring the old inline numerator spelling.

The independent real-AOT table check is recorded in `interaction-aot-v1.json`:
all six tables have exact columns and claims, selector/pole rejection and
successful recovery. This evidence supports implementation correspondence;
it does not expand the formal theorem's scope.

The subsequent counter dependency cleanup refreshes an eighth binding:
`air/lookups/tables/counter.zig` now imports `infra_trace/permutation.zig`
directly for `BitReversalTable`. The previous `infra_trace.BitReversalTable`
export aliases exactly that type. The two call sites, table mapping, signed
increments and all constraint equations are unchanged. This removes the
unnecessary execution-tracing import without changing table semantics.
