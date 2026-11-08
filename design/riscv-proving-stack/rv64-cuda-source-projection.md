# Source-derived resident lookup projection

`projection_codegen.zig` records the native raw tuple emitters through the
read-only `riscv_cpu.rv64_gkr_source` authority. The generated kernel reads
physical FIXED and MAIN columns, with the exact circle-storage previous-row law,
and emits base numerators plus eight-coordinate OM31 denominators. It preserves
zero-weight denominator slots and writes every padded lane as exactly0/1.
No expanded tuple matrix is produced or uploaded.

The explicit public-value input namespace contains epoch, sponge permutation
first ID, compact CPU initial PC and register endpoints/clocks. It is not an
additional committed PCS tree. These values must come from admitted statement
metadata; the complete proof still has to authenticate the corresponding local
terminal against the physical MAIN root. Numerical projection alone does not
provide that binding.

Secure parameters use distinct cold semantic draw-slot representatives. The
compacted-slot map enters the executable identity, independent of live field
values. Equal/zero runtime challenges therefore cannot merge unrelated wires.
Artifact checks reject changed source labels, geometry, input masks and invalid
semantic slots. The native gather API admits the actual namespace arities and
keeps U8's literal unit coefficient out of its draw slots. All challenges in the
hardware qualification are derived by the resident native OM31 channel; expected
CPU fractions are read only after completion.

The sponge raw authority now has a typed first-ID entrypoint so cold programs do
not bake a request number into their constants. The legacy integer API remains
a wrapper around that same equation body. Focused native physical proofs retain
fresh acceptance and rejection of modified MAIN/Eq/prefix/target data.

On the RTX5090,47 source role/layout cases match the native tuple authority,
including compact and paired CPU, all tables and service bridges, all nine bulk
kinds, both sponge kinds and both D64 instances. Four injected input/pole cases
are rejected; two invalid semantic mappings per case are rejected before native
dispatch. All four Compute Sanitizer tools pass. The shared arithmetic emitter
also passes20 MAIN-only composition cases across9 native roles, including compact
CPU, plus12,446 global mask positions, under all four tools. Host Safe/Fast each
pass49 tests;11 focused context guards pass. Source kernels have no spills.
Receipts are in `vectors/reports/rv64-cuda-source-projection-20261102/`.

The numerical commands now preflight an active, owned context stage and record
successful kernel dispatches in that stage. Existing borrowed-lane access already
fenced teardown; the new accounting closes the stage telemetry gap rather than
introducing a substitute synchronization path.

Reproduce the source fixtures with `zig build rv64-projection-fixtures
--build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -- OUT`.
Compile each `OUT/case-*.cu` with the native CUDA and test-harness include paths,
then link `projection_smoke.cu`, `rv64/parameters.cu`, `rv64/channel.cu` and the
existing context object. Include OUT so the generated `launches.h` is available.
The harness takes OUT as its only argument.

Source projection and the previously qualified resident GKR traversal still need
to join the physical PCS pipeline. Joined AIR, public Eq witnesses/auxiliaries,
OM31 OODS/DEEP/FRI control and proof/opening assembly remain explicit gates.
`production_ready` remains false; no complete GPU block proof is claimed here.
