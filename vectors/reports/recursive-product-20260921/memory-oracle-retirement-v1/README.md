# Retired opcode memory writer isolated

The old opcode memory-column generator's sole caller was the retired interaction
oracle. Moved its allocation/result ownership, trace-to-access writer and private
helpers into that oracle. Deleted the unused monolithic memory constraint entry.
The production memory module retains committed layout accessors and register
boundary validation, with no public old writer or old constraint constructor.

Sixteen retained production function bodies match the pre-change source exactly.
Eleven oracle function bodies match exactly after rebinding the generator name.
The oracle's private layout helpers intentionally preserve its historical behavior;
they do not define a second production authority. No protocol equations changed.

Validation:
- Focused interaction/memory gate: 13 tests passed, compile five seconds, run
  500 ms. Includes the five interaction regressions and four memory-layout tests.
- Isolation, product closure and typed proposal guards: 47 tests passed.
- Frontend inventory: two tests passed.
- Body-transfer audit and diff whitespace checks passed.
- Source conformance remains at 104 size findings, without baseline suppression.

The production memory owner is 607 lines and the test oracle is 616 lines.
No complete proof rebuild was repeated for this test-only writer relocation and
unused-entry deletion. The last full checkpoint remains separately archived;
subsequent cleanup is covered by the scoped validation here. The broader baseline
goal remains open.
