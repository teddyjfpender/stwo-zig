# Private samples shared across DEEP, composition and transcript

Previous stage: shared private claims, but composition and DEEP samples still had
public expected-value anchors. This stage removes both sets of sample anchors.

DEEP sample coordinates are located through canonical sampled_value_word bindings.
The link builder requires every coordinate exactly once. Parent admission checks
node types/ranges, duplicate links, source values and completeness. It indexes
external input reads once rather than rescanning every receipt for every node.

The existing qm31_pack_wire AIR already multiplies each scalar consume and secure
emit by the same fixed field value. New validated positive-multiplicity helpers
expose that behavior without changing its equations or semantic digest. For each
sample, the packing multiplicity equals composition graph uses plus the transcript
encoder read. Each DEEP scalar producer supplies its local graph uses plus that
packing multiplicity. The secure composition input has no independent producer;
only the pack row emits it. Three literal zero extension coordinates in each scalar
lookup tuple force the scalar representation, and canonical field-byte encoding
feeds the same secure value into transcript absorption.

DEEP scalar sources now use private boundary rows, while the composition sample
boundaries are absent. Claims retain their previous shared private sources. The
parent roster adds the existing packing AIR (twelve AIRs total). The ordinary
single-graph regression uses zero-padded packing rows. Independently reconstructed
packing schedules contain wire identities and use counts, not sample values.

The weighted packing unit checks exact scalar and secure tuples, signed
multiplicities including p-1, rejection of zero/noncanonical multiplicity, canonical
sample mapping and missing/duplicate coordinates. The full parent proof checks
all equations and lookup interactions together with transcript and Merkle paths.

This removes direct sampled-value anchors across these three consumers. Queried
trace values, FRI opening values and several challenge/root/query outputs remain
public fixture inputs. Query/path routing and rejection counts still affect fixed
structure. Thus production reusable keys/private child-proof admission, CPU/Metal,
parent-of-parent and performance qualification remain incomplete. Production still
uses Poseidon. No migration completion or speedup is claimed.

Validation (serialized ReleaseSafe):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-qm31-pack-wire test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Twelve steps succeeded; all three guarded tests passed. Weighted packing/mapping
unit: 492 ms / 2 MiB, compilation 4 seconds / 499 MiB. Combined original/parent
proof gate: 29 seconds / 6 GiB, compilation 36 seconds / 2 GiB. Single-graph FRI
regression: 5 seconds / 368 MiB, compilation 29 seconds / 2 GiB. These are fixture
qualification costs, not production recursion latency. Formatting and diff checks
passed. No broad suite was run.
