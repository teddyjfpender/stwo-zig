# Native query fusion integration

Native parent preparation now contracts admitted DEEP dot4 rows with their four
single-use scalar producers. The original full graph-input inventory is checked
before contraction. Canonical matching includes graph outputs; no source annotations
from the candidate are accepted as routing authority. The materializer reconstructs
and compares every replaced dot4, checks base-field query coordinates, requires exact
scalar metadata at multiplicity three, and rejects missing or duplicate sources.
The replacement emits multiplicity two to preserve hash and read-only consumers.

The native roster now has 20 AIRs, with native_pcs_opening4_v1 appended after the
existing dot4. Protocol version 4 and envelope version 3 bind the new geometry.
The producer/verifier use the same roster-derived columns and claim counts.
Unmatched/shared query inputs and generic dot4 rows remain in their canonical paths.

Qualification: test-blake3-native-segment ReleaseSafe passed 4/4 steps, 3/3 tests
(run 42 s / 2 GiB). Standalone AIR
closure and mutation qualification is recorded in ../2026-09-22-native-pcs-opening-air.
No speedup, production security-profile, distinct-child aggregation, parent-of-parent
or Metal completion is claimed.

## Measured result

The actual parent replaces 134 generic dot4 rows with 134 native query rows and
removes 536 scalar rows. Artifact bytes fall from 117,135 to 116,382. Current key:
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.
The codec now derives 22 claims and a 404-byte header from the 20-AIR roster.
Two same-capture pipeline jobs independently verify, including proof ownership
after worker destruction. Measured stage overlap is 1,340,673,375 ns, not an A/B
speedup. Preparation retains 461,491,951 bytes and peaks at 1,242,103,479 tracked
bytes; worker peak is 1,626,590,262 bytes. Arena capacity and padded domains mean
the logical row reduction does not imply equivalent allocated-memory savings.

The first compile exposed an unsupported generic equality operation on M31
structs; explicit field equality fixed it before the successful gate. No full
suite was run. The full gate checks existing source/value mutations and independent
verification; helper-specific adversarial tests for each new metadata rejection
remain useful additional qualification, not claimed by the standalone AIR tests.

Next: finish those admission checks, reduce repeated row materialization into the
final layout, and continue production key/multi-level/Metal qualification. Larger
production security profiles and a complete same-profile timing comparison remain
necessary before promoting performance claims or switching defaults.
