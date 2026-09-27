# Full-STARK authentication paths in the joined parent fixture

Previous turn: progress; full transcript and composition/DEEP/FRI arithmetic
shared a parent proof, but its actual captured STARK openings were unauthenticated.

This stage assembles every raw-query trace path for all four trees and every
complete FRI folding group. Trace positions use native prepareTreeQueryPositions;
lifted_leaf_plan checks repeated projected rows and orders leaf columns exactly
as native hashing does. FRI groups hash every captured value into the complete
folding subtree before following the upper path; no first-leaf shortcut is used.
Each prepared root is compared byte-for-byte with the corresponding capture
commitment. An altered sibling is checked to produce a different root.

Both tree families reuse blake3_merkle_group_witness. Each canonical M31 word is
encoded by a public byte boundary, with the exact payload use count, and sibling
words use the existing bounded private-word AIR. Live and trusted rows are built
separately; the parent roster adds that private-word AIR and combines all paths
with its existing transcript and three arithmetic graphs. Hash namespaces advance
by actual subtree/path size in [2,000,000, 3,000,000); payload words use circuit
3,000,000. Transcript and arithmetic namespaces remain separate.

Temporary per-opening subtree allocations use the test allocator and are freed
before the next opening. The retained row inventory belongs to one arena. Paths
across different raw queries are not yet deduplicated.

Scope: the parent fixture now includes transcript, composition/OODS, DEEP, FRI,
and all captured authentication paths. Arithmetic and leaf values remain public
fixture statement inputs taken from the same already native-verified capture.
They are NOT production private witness admission or a fixed reusable key. This
is still a qualification fixture, not production recursion, not parent-of-parent,
and not a production speed benchmark. CPU/Metal migration and canonical profile/
key/public-input integration remain. Production still uses Poseidon.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Eight steps succeeded; both guarded tests passed. The combined gate, including
both original and parent proofs, took 28 seconds / 6 GiB peak RSS; compilation
35 seconds / 2 GiB. The single-graph FRI regression passed in 5 seconds / 368 MiB;
compilation 27 seconds / 1 GiB. Compared with the preceding stage's 12-second /
1-GiB gate, full authentication adds substantial fixture work; no performance
gain is inferred. Formatting and diff checks passed. No broad suite was run.
