"""Witness-uniqueness analysis for per-row AIR constraint systems.

The package is deliberately split so the next phase (emitting IR from the real
`air/semantics/` modules) only has to target the shared
`riscv_air_ir_lib.ir` contract:

  riscv_air_ir_lib.ir
              serialisable constraint-system IR and its two input encodings.
  riscv_air_ir_lib.tables
              preprocessed lookup-table membership, transcribed from
              `src/frontends/riscv/air/lookups/tables/schema.zig`.
  analysis.py exact static analyses over the shared IR.
  smtlib.py   IR + membership -> SMT-LIB2 two-copy uniqueness query.
  solve.py    z3 runner over that text, with counterexample decoding.
"""
