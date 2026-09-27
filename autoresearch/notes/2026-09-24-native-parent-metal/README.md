# Canonical native parent Metal qualification and interaction dispatch

This is the native twenty-AIR BLAKE3 parent, not the detached recursive catalog.
The new focused target uses the same compact-range child and canonical parent
fixture as CPU. Both child and parent retain 70 queries and 26 PoW bits.

## Change and boundary

The admitted parent plan retains authenticated interaction programs accepted by
the backend's exact capability check. Each supported cohort stages its fixed
columns, writes owned interaction columns through the existing device kernel,
and releases temporary staging after synchronous readback. Unsupported cohorts
use the existing parallel CPU generator. CPU scratch is sized only for those
cohorts. No AIR, transcript, proof configuration, guest, or shader changes.

The diagnostic control STWO_RISCV_CPU_PARENT_INTERACTIONS=1 selects CPU
interactions in the same binary. Other GPU stages remain enabled in both arms.
This control isolates the dispatch change; it is not a CPU-versus-Metal comparison.

The focused test checks admission rejection, rekey and fixed-plan reuse, proof
ownership beyond worker destruction, independent verification and transcript replay.
Both initial runs passed all seven imported/selected tests. The canonical parent
artifact is 857591 bytes and SHA-256
87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b,
identical to the qualified CPU artifact.

## Initial diagnostic

Baseline parent stage sum: 19.352740 s; device interactions: 14.055196 s.
Interaction generation alone: 5.796623 s to 0.703408 s.
Device telemetry reports 20 framework interaction dispatches, while composition
still has five device components and seventeen CPU components. Dispatch count
is not component count: scans contribute dispatches.

These single observations exclude preparation and verification. The same-binary
interleaved experiment in measure.py records complete fixture wall time separately,
including child proof, parent preparation, verification, and teardown; compilation
is excluded. Its raw logs, results.json, summary.json, binary.json and frozen core
AOT bundle provide the reproduction evidence.

This checkpoint does not supersede the historical CSP basket, qualify a complete
recursive tree, demonstrate subsecond recursion, or establish superiority to ZisK.
Next work includes remaining native composition coverage and shared CSP trace costs.

## Matched result

Four serial frozen-binary runs in control/candidate/candidate/control order,
two observations per arm. Every artifact has the identical hash above and all
canonical verification, replay, rekey and ownership assertions pass.

| Metric | CPU interaction control | Device interactions |
| --- | ---: | ---: |
| Complete fixture wall median | 32.120913 s | 26.691756 s |
| Recorded parent stages median | 19.141332 s | 14.101566 s |
| Interaction generation median | 5.711809 s | 0.697715 s |
| Maximum resident set | 20,886,847,488 B | 20,883,177,472 B |
| Peak physical footprint | 27,381,526,816 B | 27,381,805,560 B |

Complete fixture time falls 16.9%; recorded parent stages fall 26.3%;
interaction generation is 8.2x faster. Peak memory is effectively unchanged.
Physical footprint is process-wide and exceeds the separately tracked parent
allocator peak; the 24 GiB parent allocator budget is not a total process limit.
Two samples per arm are a focused engineering comparison, not a final ten-sample
CSP qualification or complete production-tree latency.

Reproduce after building the authenticated core bundle:
```sh
STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-native-parent-metal/measure.py
```
The second command uses this directory's frozen parent-test and core bundle.

The focused CPU canonical parent regression also passes after this change
(cpu-regression.log), with the identical artifact hash and all canonical replay,
rekey and output-lifetime checks. This independently instantiates the CPU backend
fallback; no full repository suite was run for this localized dispatch change.
