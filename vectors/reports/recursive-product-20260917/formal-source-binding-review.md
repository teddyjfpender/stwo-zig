# Remaining source binding review

The new load/store shape and range argument are proved in both directions in Lean.
The other 38 programs still normalize exactly to their prior reviewed layouts.
Six shared source files have older recorded byte hashes in those programs.
`formal-source-binding-review.patch` records every change against the exact old
Git revision recovered by matching each recorded SHA-256.

- M31 inversion uses an addition chain: the final exponent is
  4 * (2^29 - 1) + 1 = 2^31 - 3 = p - 2, retaining the previous exponent.
- Access-clock admission factors its predicate into native/symbolic operations.
  For a nonzero non-reserved clock, floor(clock / 4) < count is equivalent to
  clock <= 4 * count - 1; the zero rule is retained. The native regression test
  compares the predicates across clock/count/zero-policy combinations.
- Symbolic arena ownership becomes thread-local; square emits self * self.
- Lookup entry adds a relation-parameter appender with z followed by alpha powers;
  existing entry semantics are unchanged.
- Opcode entry changes are load/store lookup/batch/domain test expectations.
- Opcode manifest adds the reviewed load/store range_check_8_8 domain.

Refresh the remaining source identities and their exact public-program identity
pins from the verified exports, then rerun generated-binding, audit and coverage
gates. This review does not claim the refresh or those checks are complete.
