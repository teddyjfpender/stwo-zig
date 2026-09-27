# Native BLAKE3 DEEP preparation and shared samples

The canonical PCS-DEEP graph now evaluates the real verified BLAKE3 native V2
capture: 16,069 nodes and 34 zero outputs. The adapter accepts the engine's
concrete verified capture, validates its authorities, derives column logs and
ordered sample layouts from GeometryV2, and uses the hash-independent owned
PCS capture adapter and existing DEEP graph. Query count and blowup come from
the caller's PCS configuration. No standalone fixture geometry is substituted.

All 705 sampled values (2,820 base-field coordinates) now have explicit scalar
routes from the native composition/transcript encoding producers to DEEP inputs.
The shared rows replace the old payload scalar rows: each sample producer gains
exactly one DEEP consumer, while aggregate-claim producers remain unchanged.
DEEP destination weights are derived from the canonical arithmetic graph.
The producer node map is independently checked against native binding roles;
equal witness values cannot authorize permuting sample identities. Native and
DEEP evaluations must agree coordinate by coordinate. Fixed schedules exclude
values. The complete parent must include these returned rows exactly once.

The integration check asserts multiplicities and fixed-row parity, rejects a
permuted native sample map, and changes a sample to verify canonical DEEP
rejection with UnsatisfiedCircuit.

Initial integration passed all mathematical checks but failed the allocator leak
gate. pcs_arithmetic_capture.Owned.init copied its arena into the return value
before allocating the owned witness slices; a later arena growth was therefore
not retained by the returned owner. The constructor now allocates the entire
witness before transferring the arena. A 512-column allocation-failure regression
forces growth beyond the initial arena block; the earlier tiny case fit in one
block and did not expose this defect. No admission check was removed.

Final serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-pcs-arithmetic-capture test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 8/8 steps, 4/4 tests passed with no allocator leaks.
Capture ownership/allocation-failure gate: 664 ms / 1 MiB, compile 4 s / 486 MiB.
Native gate: 20 s / 1 GiB, compile 58 s / 4 GiB. Formatting and git diff --check
passed. No broad suite ran and no build remains live. The initial failure log
is retained rather than counted as a successful gate.

Scope: native graph evaluation and row preparation. The complete joined parent
STARK, public-boundary/native-sum joins, challenge fanout, query/path joins and
FRI input sharing remain unfinished. Production keys, statement-independent
preprocessing, Metal and parent-of-parent qualification remain outstanding.
This q1/PoW0 correctness gate establishes no production speedup.
