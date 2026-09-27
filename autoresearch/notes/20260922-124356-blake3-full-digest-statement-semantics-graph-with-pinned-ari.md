---
title: BLAKE3 full-digest statement semantics graph with pinned arithmetic seal
author: Teddy Pender
created_utc: 2026-09-22T12:43:56Z
---

# BLAKE3 statement semantics graph

The existing statement graph contract, tracked builder and equations now accept
a compile-time format selection. The legacy facade instantiates its unchanged
412-word format and retains its exact graph seal. The new BLAKE3 facade selects
the 525-word Span, BLAKE3 input-witness profile and format-separated identity
domain. Edge constraints use sixteen limbs; leaf constraints bind the explicit
format version. Binary nodes copy common job/header words from verified children,
retaining the existing requirement that child statements have been authenticated.

New pinned geometry: 2,416 inputs (2,100 statement, 3 selectors, 313 private),
10,912 arithmetic nodes, 2,916 zero-output constraints. Identity:
`98a3f31ab5b46a4b4ddba58affb5139c0a76d0190444f3f278ab73bc51a0855e`.

Qualification:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed; final outer build reported 12 seconds and 833 MB peak RSS. The gate now
has a 38-named-test floor and includes all eleven existing statement graph tests
(sealed geometry, determinism, adversarial cases, allocation failures), the prior
native codec/input-AIR gates and four new BLAKE3 graph tests. New cases cover:

- New graph seal and all 896 digest-limb coordinates in its input schedule.
- Distinct-child arithmetic folding; mutations to each of sixteen limbs in both
  continuation digests, the carried input edge and the carried output edge.
- Leaf version mismatch; combined graph/input-AIR evaluation of valid full-digest
  statements and rejection of a 65536 digest limb. The test explicitly confirms
  that the graph alone does not range-check an opaque job identity: the sealed
  input AIR performs that essential check.
- Executed-plus-padding folds, empty leaves and all-empty subtrees.

The graph's geometry and digest checks remained fail-closed while deriving the
new constants. No unsealed graph is admitted. Native and arithmetic tests share
one fixture module. No full recursive proof, new authenticated key, BLAKE3 identity
preimage/hash binding or production source/capture integration is claimed here.

Next: migrate the row-10 statement provider and its relation/schedule authority to
525 words, close provider/consumer tuples with this graph's input schedule, then
migrate identity preimages, hash bindings and artifact/key admission. Production
recursion and the wider Poseidon removal goal remain incomplete.
