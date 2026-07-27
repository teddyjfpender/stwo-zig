"""Witness-uniqueness analysis for per-row AIR constraint systems.

The package is deliberately split so the next phase (emitting IR from the real
`air/semantics/` modules) only has to target `ir.py`:

  ir.py       serialisable constraint-system IR, its two input encodings, and
              the static analyses the emitter depends on (bounds, degree).
  tables.py   preprocessed lookup-table membership, transcribed from
              `src/frontends/riscv/air/lookups/tables/schema.zig`.
  smtlib.py   IR + membership -> SMT-LIB2 two-copy uniqueness query.
  solve.py    z3 runner over that text, with counterexample decoding.
"""
