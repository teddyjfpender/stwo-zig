# Generated native OM31 composition on RTX 5090

The cold exporter records the frontend's own MAIN-only CPU, ALU, BINARY, SHIFT,
LS, JALR, MUL and DIV equations over its OM31 symbolic lane. Every recorded
residual agrees with a separate native OM31 invocation before device export:
90,112 residual comparisons including a mixed secure-parameter/mask fixture.
These are random domain columns, not an honest Ethereum execution witness.

The CUDA lowering uses M31 for base-only DAG nodes, OM31 for secure nodes,
M31-by-OM31 scaling for mixed multiplication, native reversed random powers,
trace vanishing inverses, and accumulation into existing output columns.
An iterative root-first schedule loads dependencies near their first use and
accumulates residual weights immediately. Duplicate roots retain every weight.
All equations and signed mask offsets are bound by the IR identity; executable
identity additionally binds the exporter and the numerical headers. Invocation
parameters are separate from executable identity. This does not yet establish a
production semantic parameter map or a complete fixed-shape AOT registry.

All eight MAIN-only roles and the mixed fixture pass on hardware, with complete
and three-tile launches (18 cases), nonzero initial accumulators and all eight
output coordinates. A further 12,446 hardware mask comparisons use the real core
index utility as oracle: equal and lifted domain heights and offsets -128, -2,
-1, 0, 1, 2, 127. All four Compute Sanitizer tools pass. Integration Safe/Fast
passes 38 tests each.

The final compiler reports zero spills in all nine kernels. Root-first emission
reduces LS registers from168 to114, MUL from186 to128 and DIV from156 to128.
CPU changes from138 to80, but its final fixture also changes public values from
zero to valid nonzero endpoints, so that comparison is not an isolated schedule
measurement. No wall-time speedup is established by register counts.

Reproduce the cold fixture export:

```
zig build rv64-composition-fixtures --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -- /tmp/rv64-composition-fixtures
```

Compile `generated.cu` and `tests/cuda/rv64/composition_smoke.cu` offline with
NVCC12.8, SM120, the native include directory and the existing context object.
Run the smoke with the fixture directory, then repeat under memcheck, initcheck,
racecheck and synccheck with error-exitcode99. Raw logs are in `gates/`, and
`artifacts.json` pins the generated source and numerical fixtures without adding
large witness artifacts to Git. No runtime compiler is added to the prover.

This qualifies numerical lowering only. MAIN-only arithmetic does not replace
local GKR terminal authentication or global RAM/KIO/Wire closure. Joined GKR
roles, derived public auxiliaries, truth providers, invocation pointer/custody
checks and source-bound AOT admission still need integration. There is no complete
Ethereum GPU proof or end-to-end throughput claim, and production readiness
remains false.
