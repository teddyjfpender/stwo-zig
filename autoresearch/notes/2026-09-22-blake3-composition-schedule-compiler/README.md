# BLAKE3 composition schedule compiler

The composition graph reference contract and schedule compiler now instantiate
from one format-parameterized implementation. Legacy graph, reference and schedule
domains remain unchanged. BLAKE3 uses separate domains and the canonical 525-word
Span size, retaining distinct reference/row types at the API boundary.

For the zero-extra-input profile, recursion input count is 537: parent selector,
three child selectors, 525 statement words, four composition-randomness words and
four OODS-point words. This shifts later inputs coherently rather than merely
widening an admission bound. The source-index mapping and compiled-row validator
share the same format count. Legacy scalar VM-root and field-public extension
profiles are explicitly rejected in the new format pending their migration.

Qualification command:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed; final outer build reported 13 seconds and 838 MB peak RSS. The focused
gate has a 54-named-test floor and includes all five legacy composition compiler
tests alongside two new BLAKE3 tests. New tests check every statement coordinate,
subsequent randomness placement, unsupported profiles, authenticated synthetic
reference compilation, all 525 compiled statement rows, missing-anchor rejection,
out-of-range schedule words, changed input bindings and cross-format graph seal
substitution. The synthetic reference is a compiler fixture, not a production
recursive verifier circuit; no cryptographic proof or performance result is implied.

Remaining: vm_air_composition_input_witness still imports the legacy compiler.
Connect a format-specific witness profile to the new compiler, separate its
binding/schedule domains, migrate its source bounds and check the row-10/row-18
child-word multiplicities. Source/public-claim projections, identity hash bindings,
artifact/key admission and full recursive proving remain pending.
