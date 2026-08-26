# Team-B reviewed AIR capsules: typed-authority rebind

Status: audited and mechanically gated on 2026-08-12.

The six Team-B symbolic AIR exports changed raw SHA-256 when production
construction moved from the retired family semantics modules to
`constraint_program.Builder` and the typed authority evaluators:

- `typed_shifts_reg_authority.zig`
- `typed_shifts_imm_authority.zig`
- `typed_load_store_authority.zig`
- `typed_mul_authority.zig`
- `typed_mulh_authority.zig`
- `typed_div_authority.zig`

This is an expression-interning change, not a polynomial protocol change. The
typed builder constructs direct and lookup sections through one authority. That
changes when shared scalar subexpressions enter the recording arena and thus
changes node IDs and raw JSON bytes. It does not, by itself, justify updating a
reviewed Lean capsule's source digest.

## Rebinding evidence

`scripts/riscv_air_ir_equivalence.py` independently parses both exports and
expands every supported DAG node (`col`, `const`, `neg`, `add`, `sub`, `mul`)
into a sparse polynomial over the declared prime field. It rejects unknown
operators, malformed/non-topological references, duplicate columns, and any
unsupported JSON shape. The comparison preserves order and requires equality
of:

1. family, field modulus, notes, column names and roles;
2. every direct-constraint polynomial;
3. every lookup role, domain, numerator polynomial, and tuple polynomial;
4. the declared unmodelled-bus-request count.

The audit passed for all six families. Their column, node, constraint, lookup,
and unmodelled-request counts are unchanged. The old and new raw hashes and the
shared normalized polynomial hashes are sealed in
`formal/riscv-refinement/team-b-air-semantic-equivalence-v1.json`.

The receipt deliberately does not claim witness-generator equivalence,
cross-row/multiset closure, or Sail equivalence. Those remain owned by their
separate differential, proof, and formal gates.

## Independent gates

The rebind is accepted only when all of the following pass:

```text
python3 scripts/riscv_air_ir_equivalence.py check \
  --candidate-dir zig-out/uniqueness-ir \
  --receipt formal/riscv-refinement/team-b-air-semantic-equivalence-v1.json

python3 scripts/riscv_team_b.py check \
  --air-ir-dir zig-out/uniqueness-ir

python3 scripts/riscv_refinement.py verify \
  --no-export-air \
  --air-ir-dir zig-out/uniqueness-ir \
  --air-program-ir-dir zig-out/refinement-air-ir-v2 \
  --reuse-committed-sail-evidence
```

The first gate proves the migration-specific polynomial equality and binds the
new raw hashes. The second rechecks those raw hashes against the Lean capsules
and validates their theorem namespace and mutation inventory. The third builds
the Lean refinement package and verifies the wider AIR/Sail evidence graph.
