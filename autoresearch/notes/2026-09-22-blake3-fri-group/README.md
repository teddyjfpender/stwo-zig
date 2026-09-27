# Complete typed BLAKE3 FRI folding subtree — 2026-09-22

Previous-turn classification: progress. It generated and verified actual native
PCS captures, identified FRI capture geometry, and qualified one original leaf
path. Its limitation was explicit: the other leaf values contributed only to
host-computed sibling digests.

This stage implements a reusable complete-subtree witness from authenticated
payload word ranges. All leaves use canonical BLAKE3 frame routing; every pair
of child digests feeds a typed parent hash. Intermediate public digest sinks are
removed and producer use counts match the consumers. The subtree root feeds the
private upper authentication path. Each internal node is computed once, so this
uses O(leaf_count + upper_depth) hashes instead of duplicating ancestor paths.
The module uses existing AIRs and changes no protocol vectors or identities.

The focused test generates actual native PCS captures for fold1/2/4 and their
remaining tail layers, prepares complete typed groups and compares full roots.
For the fold4 first layer, all 16 QM31 tuples feed canonical field-byte encoding,
four packed leaf hashes and three subtree merges, then the upper path, in one
six-component CPU outer proof. Changing the LAST leaf's final source tuple
changes the independently admitted preprocessing and is rejected. Live/trusted
preprocessing matches across all six components. Invalid non-power-of-two leaf
counts, overlapping source namespaces, path indices and value counts reject.

The fixture supplies public auxiliary source tuples. The reusable group builder
itself only receives a caller identity/range and shape for trusted preprocessing;
its leaf bytes and intermediate digests do not enter fixed columns. The field
encoder is what turns arithmetic tuples into canonical payload words.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-group -Doptimize=ReleaseSafe --summary all
```

Final result: four steps succeeded; one guarded test passed, approximately
3 seconds runtime, max RSS 375 MiB; compilation 22 seconds on M5 Max.
Formatting and diff checks pass. One initial compilation failed on a reserved
identifier in the new test; it was corrected before the successful gate.
This is integration evidence, not a performance measurement. Test PCS uses
17 queries and 4 PoW bits; outer proof uses development parameters.

Still unfinished: production FRI/DEEP arithmetic wire admission, full transcript
and query connection, production key/suite/artifact identities, Metal backend,
and parent-of-parent qualification. Poseidon remains the production default.
No production timing or soundness improvement is claimed. The original active
performance goal and the later BLAKE3 migration priority remain unfinished.
