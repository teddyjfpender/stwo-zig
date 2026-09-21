# Canonical detached leaf command, 2026-09-18

The detached leaf command now owns explicit output and pinned key admission. Native
ingress, detached production and execution workloads have dedicated source owners;
the command no longer imports the legacy proof test harness or broad CPU integration
facade. The no-argument legacy proof fallback and retired workload flags are removed.

CPU and Metal install `recursive-segment-v2-detached-leaf-prove` and
`recursive-segment-v2-detached-leaf-prove-metal`, respectively, through
`build-recursive-segment-v2-detached-leaf-producer`. The former concrete outer
executable/build/run names are removed. Explicit legacy test targets remain tests.
Execution-only workload inspection retains its separate executable.

`summary.json` records passing fresh CPU/Metal/AOT four-segment products: 384
checks, including fresh serialized verification and substitution rejection, with
all 21 canonical artifacts identical to the canonical identity baseline. Source
snapshots matched across backends. Focused checks passed: three parser tests,
33 source-ownership tests, four installed command rejections without output
creation, and four source-transfer checks. Backend summaries and the qualified
source snapshot are adjacent; no complete suite was rerun.

Remaining work is broader legacy parent/temporal route and public API retirement,
followed by final useful 1/2/4/8 continuation qualification on the cleaned surface.
This does not establish complete frontend typing or production security admission.
Speed work remains deferred.
