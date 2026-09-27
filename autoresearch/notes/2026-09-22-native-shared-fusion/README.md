# Shared typed fusion in native BLAKE3 recursion

The detached and native assemblers now use one owned arithmetic materializer.
It preserves the original authenticated graph and public terms, reserves canonical
dot4 matches before FMA matches, and counts outputs and exports when deciding
which intermediate wires may disappear. Native lowering selects segment lanes;
detached lowering selects binary lanes. No new arithmetic equations were added.

The native roster replaces its multiply AIR with the existing FMA AIR and appends
the existing dot4 AIR (19 AIRs total). Parameter handling follows AIR declarations.
The producer, verifier and codec derive geometry from that roster. Native protocol
version 3 and envelope version 2 reject older identities; the current diagnostic key
is `2585aff8b8d2d2ed75c595f524e8bebc0bf90f945df678634a8d217aa0453faa`.

## Results

| Measurement | Result |
| --- | ---: |
| Dot4 / FMA matches | 777 / 5,843 |
| Arithmetic rows before / after | 29,488 / 18,206 |
| Arithmetic row reduction | 11,282 (38.26%) |
| Artifact bytes before / after | 111,428 / 117,135 |
| Preparation peak tracked bytes | 1,242,103,479 |
| Prepared retained bytes | 461,491,919 |
| Worker peak tracked bytes | 1,626,401,846 |
| Two-job preparation/proving overlap | 1,350,003,667 ns |

These are structural and ownership measurements, not an A/B speedup. The artifact
increased by 5,707 bytes. Padded domains and other components can outweigh row
savings. The pipeline proves two jobs from the same captured child; it does not
qualify distinct-child aggregation or parent-of-parent. Profiles remain diagnostic
child q1/PoW0 and parent q8/PoW0. No production or Metal completion is claimed.

## Qualification and reproduction

The combined ReleaseSafe build used:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-recursive-segment-v2-detached-parent-prepare -Doptimize=ReleaseSafe --summary all
```

The native target passed 3/3 tests (42 s, 2 GiB maximum RSS), covering actual proof
production, independent verification, codec roundtrip, rejection checks, reused
plan/commitment/workspace and budget ownership after worker destruction.
The combined command exited 1 because detached genuine-child preparation lacked
fixture environment variables; the snapshot test passed. The separate direct run
confirmed `EnvironmentVariableNotFound`, preserved in the detail log.

After restoring the independently recorded fixture paths/pins from
`vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/detached-parent-assembly-seventh-process.json`,
the already-built detached binary passed 2/2 tests, exit 0. Both child owners were
destroyed before final checks; 1,121,856 relation contributions closed exactly
with zero unmatched tuples. Mutation, snapshot and failed-finalization checks
passed. This is preparation qualification, not a new detached parent proof.

`fixture-env.json` stores repo-relative paths and the historical independent pins.
To reproduce, resolve its path values against the repository root, export them,
and run the focused detached build target above. The qualified binary was
`src/integrations/riscv_cpu/.zig-cache/o/99acba141995836d6d642a0ac679964b/test`.
After qualification, only a comment and the census log label were updated in
source; neither changes arithmetic or proof behavior. Source snapshots reflect
those final descriptive edits. The native proof gate was not redundantly rerun.

Larger fused PCS/DEEP components beyond dot4/FMA, direct final-layout generation,
production reusable keys, multi-level recursion and Metal remain in scope.
