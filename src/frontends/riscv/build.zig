const std = @import("std");

/// Fewest tests this package's test binary must contain.
///
/// Measured floor on this tree: 1061. Zig collects a `test` only from a file it was
/// made to analyse, so before the explicit inventory this step silently compiled
/// only 319 of the then-461 named tests -- `refAllDecls` in a `mod.zig` does not
/// pull a file's tests in, and nothing said so. A binary that compiled almost
/// nothing still exits 0 in milliseconds, so the count is the only thing that
/// distinguishes this step from an empty shell.
///
/// `mod.zig` reaches every test-bearing file through `test_inventory.zig`, and
/// `test_inventory_test.zig` fails when a file is missing from that list. This
/// floor is the backstop for the wiring itself. Raise it deliberately as the
/// suite grows; never lower it to make a build pass.
const test_floor = 1078;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(
        bool,
        "check-only",
        "Type-check focused roots without emitting or running test binaries",
    ) orelse false;
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const proof_wire = b.createModule(.{
        .root_source_file = b.path("../../interop/proof_wire/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", core);
    const postcard = b.createModule(.{
        .root_source_file = b.path("../../interop/postcard.zig"),
        .target = target,
        .optimize = optimize,
    });
    postcard.addImport("stwo_core", core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    const typed_air_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "../../../design/typed-air/artifacts/embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const typed_air_h009_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "../../../design/typed-air/artifacts/h009_embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const typed_air_h010_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "../../../design/typed-air/artifacts/h010_embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const frontend = b.addModule("stwo_riscv_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_api", prover_api);
    frontend.addImport("stwo_prover_engine", prover);
    frontend.addImport("interop_postcard", postcard);
    // Test-only consumers import this name explicitly. Production frontend
    // modules never reference the design artifact package.
    frontend.addImport("typed_air_artifacts", typed_air_artifacts);
    frontend.addImport("typed_air_h009_artifacts", typed_air_h009_artifacts);
    frontend.addImport("typed_air_h010_artifacts", typed_air_h010_artifacts);

    const tests = b.addTest(.{ .root_module = frontend });
    const run_tests = b.addRunArtifact(tests);
    // ReleaseFast production skips the duplicate pre-commit semantic pass.
    // The package CI lane opts back in so the validator and its exact
    // InvalidSemanticWitness verdict remain exercised in the shipping mode.
    run_tests.setEnvironmentVariable(
        "STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS",
        "1",
    );
    // The floor reads the run's test-name table, which only the invocation that
    // actually executed the binary populates: a cache hit leaves it null and the
    // floor would then have to fail closed on every repeat of a correct run.
    // Re-running an already compiled suite costs its runtime, under a second.
    run_tests.has_side_effects = true;
    const test_step = b.step(
        "test",
        "Compile and test the stwo_riscv_frontend package",
    );
    test_step.dependOn(TestCountFloor.add(b, run_tests, test_floor));

    const manifest_mode = b.option(
        []const u8,
        "typed-air-manifest-mode",
        "Compatibility artifact mode: check (default) or update",
    ) orelse "check";
    const manifest_tool_root = b.createModule(.{
        .root_source_file = b.path("compat_manifest_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    manifest_tool_root.addImport("stwo_core", core);
    manifest_tool_root.addImport("stwo_prover_engine", prover);
    const manifest_tool = b.addExecutable(.{
        .name = "riscv-typed-air-manifest",
        .root_module = manifest_tool_root,
    });
    const run_manifest_tool = b.addRunArtifact(manifest_tool);
    run_manifest_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_manifest_tool.addArgs(&.{
        manifest_mode,
        "design/typed-air/artifacts/m3-compat-v1",
    });
    b.step(
        "typed-air-manifest",
        "Check or explicitly update typed-AIR compatibility artifacts",
    ).dependOn(&run_manifest_tool.step);

    const frontier_mode = b.option(
        []const u8,
        "typed-air-frontier-mode",
        "H-009 Poseidon cost-frontier artifact mode: check (default) or update",
    ) orelse "check";
    const frontier_tool_root = b.createModule(.{
        .root_source_file = b.path("materialization_frontier_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontier_tool_root.addImport("stwo_core", core);
    const frontier_tool = b.addExecutable(.{
        .name = "riscv-typed-air-frontier",
        .root_module = frontier_tool_root,
    });
    const run_frontier_tool = b.addRunArtifact(frontier_tool);
    run_frontier_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_frontier_tool.addArgs(&.{
        frontier_mode,
        "design/typed-air/artifacts/h009-poseidon2-cost-v1",
    });
    b.step(
        "typed-air-frontier",
        "Check or explicitly update the H-009 Poseidon cost-frontier artifacts",
    ).dependOn(&run_frontier_tool.step);

    const static_profile_mode = b.option(
        []const u8,
        "typed-air-static-profile-mode",
        "P-002 native-family profile artifact mode: check (default) or update",
    ) orelse "check";
    const static_profile_tool_root = b.createModule(.{
        .root_source_file = b.path("static_profile_registry_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    static_profile_tool_root.addImport("stwo_core", core);
    static_profile_tool_root.addImport("stwo_prover_api", prover_api);
    static_profile_tool_root.addImport("interop_postcard", postcard);
    const static_profile_tool = b.addExecutable(.{
        .name = "riscv-typed-air-static-profile",
        .root_module = static_profile_tool_root,
    });
    const run_static_profile_tool = b.addRunArtifact(static_profile_tool);
    run_static_profile_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_static_profile_tool.addArgs(&.{
        static_profile_mode,
        "design/typed-air/artifacts/p002-native-family-static-profile-v1",
    });
    b.step(
        "typed-air-static-profile",
        "Check or explicitly update the P-002 native-family profile artifacts",
    ).dependOn(&run_static_profile_tool.step);

    const layout_benchmark_root = b.createModule(.{
        .root_source_file = b.path("poseidon_layout_benchmark_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    layout_benchmark_root.addImport("stwo_core", core);
    layout_benchmark_root.addImport("stwo_prover_engine", prover);
    layout_benchmark_root.addImport(
        "typed_air_h009_artifacts",
        typed_air_h009_artifacts,
    );
    layout_benchmark_root.addImport(
        "typed_air_h010_artifacts",
        typed_air_h010_artifacts,
    );
    const layout_benchmark = b.addExecutable(.{
        .name = "riscv-poseidon-layout-benchmark",
        .root_module = layout_benchmark_root,
    });
    // The process-resource adapter uses Darwin/Linux libc rusage surfaces.
    layout_benchmark.linkLibC();
    const run_layout_benchmark = b.addRunArtifact(layout_benchmark);
    run_layout_benchmark.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    if (b.args) |args|
        run_layout_benchmark.addArgs(args)
    else
        run_layout_benchmark.addArg("check");
    b.step(
        "typed-air-layout-benchmark",
        "Check H-010 correctness or run one isolated experimental sample",
    ).dependOn(&run_layout_benchmark.step);
    b.step(
        "typed-air-layout-benchmark-install",
        "Install the isolated H-010 runner for fresh-process host sampling",
    ).dependOn(&b.addInstallArtifact(layout_benchmark, .{}).step);

    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-isa",
        .description = "Run only RISC-V ISA authority and decoder tests",
        .root = "isa_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-runner",
        .description = "Run only RISC-V execution-runner tests",
        .root = "runner_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-main-trace-plan-execution",
        .description = "Run only bounded main-trace plan and production execution tests",
        .root = "main_trace_plan_execution_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-poseidon-witness-work",
        .description = "Run exact sparse-memory and guest-Poseidon work-receipt tests",
        .root = "poseidon_witness_work_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 8,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-interaction-witness-work",
        .description = "Run exact relation-challenge and Tree-2 work-receipt tests",
        .root = "interaction_witness_work_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 3,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-semantics",
        .description = "Run only RISC-V instruction-family AIR tests",
        .root = "air_semantics_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-semantic-component",
        .description = "Run only semantic-component prepared-domain and resource tests",
        .root = "semantic_component_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{ "semantic component", "semantic prepared" },
        .minimum = 8,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-hash-component-prepared",
        .description = "Run only memory-hash prepared-domain and stack-certificate tests",
        .root = "hash_component_prepared_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 9,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-static-profile",
        .description = "Run only typed-AIR static profiler tests",
        .root = "air_static_profile_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-static-profile-registry",
        .description = "Run the complete native typed-AIR static profile registry",
        .root = "air_static_profile_registry_test_root.zig",
        .imports_typed_air_artifacts = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-runtime-profile",
        .description = "Run the authenticated typed-AIR/runtime profile join tests",
        .root = "air_runtime_profile_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-proof-phase-meter",
        .description = "Run the exact five-region witness/proving phase-meter state machine",
        .root = "proof_phase_meter_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-function-frames",
        .description = "Run Cairo-style frame isolation and activation-relation tests",
        .root = "air_function_frames_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-function-body-lowering",
        .description = "Run bounded authenticated inline-function body lowering tests",
        .root = "air_function_body_lowering_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-function-body-ownership",
        .description = "Run sealed per-function body ownership and lowering tests",
        .root = "air_function_body_ownership_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-air-function-activation-logup",
        .description = "Run live compiler-owned function activation LogUp tests",
        .root = "air_function_activation_logup_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-lookup-batching",
        .description = "Run compiler-selected LogUp planning and row execution tests",
        .root = "lookup_batch_test_root.zig",
        .imports_prover_engine = true,
        // A-014 cannot advance on an empty shadow-planner binary. Keep the
        // authority, collision, differential, and execution inventory wired.
        .minimum = 16,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-lookup-source-ingest",
        .description = "Run exact opcode-source ingestion and rollback tests",
        .root = "lookup_source_ingest_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 5,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-lookup-table-interaction",
        .description = "Run lookup-table interaction parity and rollback tests",
        .root = "lookup_table_interaction_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 6,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-opcode-interaction",
        .description = "Run scalar/packed opcode interaction parity and rollback tests",
        .root = "opcode_interaction_test_root.zig",
        .imports_prover_engine = true,
        .minimum = 11,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-lookup-batching-edit",
        .description = "Run the lightweight authenticated lookup-batch planner edit loop",
        .root = "lookup_batch_edit_test_root.zig",
        .filters = &.{"lookup batch planner:"},
        .minimum = 7,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-lookup-polynomial-v2-edit",
        .description = "Run the lightweight variable-partition polynomial-authority edit loop",
        .root = "lookup_polynomial_v2_edit_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"lookup polynomial v2:"},
        .minimum = 4,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-row-windows",
        .description = "Run compiler-owned row-window, mask, and ownership tests",
        .root = "row_window_test_root.zig",
        .imports_prover_engine = true,
        // A-013 spans both row-window authority and its production component
        // consumer; losing either half invalidates the focused closure gate.
        .minimum = 16,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-row-windows-edit",
        .description = "Run the lightweight typed row-window authority edit loop",
        .root = "row_window_edit_test_root.zig",
        .filters = &.{"row-window v1:"},
        .minimum = 10,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-row-window-expressions-v2-edit",
        .description = "Run the lightweight shifted-expression authority edit loop",
        .root = "row_window_expression_v2_edit_test_root.zig",
        .filters = &.{"row-window expression v2:"},
        .minimum = 5,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-guest-precompile",
        .description = "Run only proof-side guest-precompile protocol tests",
        .root = "guest_precompile_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-interaction-trace-plan",
        .description = "Run the prepared Tree-2 planning and execution tests",
        .root = "interaction_trace_plan_execution_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-protocol",
        .description = "Run the frozen recursion protocol and native boundary tests",
        .root = "recursion_protocol_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-transcript-v2",
        .description = "Run exact generic-channel V2 scheduled transcript parity tests",
        .root = "transcript_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-pair-node",
        .description = "Run the authenticated native R-009 pair-node boundary tests",
        .root = "pair_node_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-temporal-pair",
        .description = "Run the V2 adjacent-span temporal pair authority tests",
        .root = "temporal_pair_node_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-vm-composition",
        .description = "Run only the row-18 VM AIR authority and composition graph tests",
        .root = "recursion_vm_composition_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-composition-recorder",
        .description = "Run the compile-isolated authenticated AIR graph recorder tests",
        .root = "recursion_air_r012_composition_circuit_dev_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-composition-v3",
        .description = "Run the versioned 39+2 shared recursion composition authority tests",
        .root = "recursion_air_composition_v3_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-composition-v3-session",
        .description = "Run only the V3 universal orchestration and heterogeneous-session tests",
        .root = "recursion_air_composition_v3_test_root.zig",
        .imports_prover_engine = true,
        // A child-only filter can exclude the root test that imports the child
        // modules, so those named tests are never discovered. One shared V3
        // prefix selects the root compile gate, six authority/session tests,
        // and the V3.1 active-empty E2E. The floor makes import/filter drift
        // fail instead of running zero.
        .filters = &.{"V3"},
        .minimum = 8,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-outer-sources",
        .description = "Run only segment outer-proof sources for rows 0 through 17 and 35",
        .root = "recursion_outer_sources_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-binary-transcript-source",
        .description = "Run only the binary-node rows 0 through 9 source tests",
        .root = "binary_transcript_outer_source_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-leaf-bundle",
        .description = "Run only the composed segment-leaf outer bundle",
        .root = "segment_leaf_outer_bundle_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"R-012 segment-leaf bundle"},
        .minimum = 4,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-leaf-outer-v2",
        .description = "Run the authenticated V2 segment-leaf outer authority tests",
        .root = "segment_leaf_outer_authority_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-transcript-source-v2",
        .description = "Run the V2 scheduled-transcript outer source tests",
        .root = "segment_transcript_outer_source_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-transcript-components-v2",
        .description = "Run the V2 rows 0 through 9 component and tree-writer gates",
        .root = "segment_transcript_outer_components_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-statement-source-v2",
        .description = "Run the V2 rows 10 and 11 statement authority gates",
        .root = "segment_statement_outer_source_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-public-source-v2",
        .description = "Run the V2 rows 12 through 17 public-spine source gates",
        .root = "segment_public_outer_source_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-public-components-v2",
        .description = "Run the V2 public-spine typed AIR and component gates",
        .root = "segment_public_outer_components_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-publication-provider-v2",
        .description = "Run the committed SegmentV2 verifier-input provider authority tests",
        .root = "segment_publication_input_provider_authority_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-outer-manifest-v2",
        .description = "Run the versioned 38-component segment outer manifest tests",
        .root = "segment_outer_adapter_manifest_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-outer-cohort-v2",
        .description = "Run the strict 38-row SegmentV2 cohort and shared-schedule gates",
        .root = "segment_outer_cohort_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-outer-noncore-audits-v2",
        .description = "Run exact-domain custody for SegmentV2 non-core Tree-2 rows",
        .root = "segment_outer_noncore_audits_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-segment-boundary-components-v2",
        .description = "Run the concrete V2 boundary source component adapter tests",
        .root = "segment_boundary_components_v2_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-fri-profile-measurements",
        .description = "Run exact receipt-backed frozen-V1 to V1.1 FRI profile comparisons",
        .root = "fri_profile_frontier_measurement_test_root.zig",
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-parent-transcript-source",
        .description = "Run the authenticated two-child parent transcript source tests",
        .root = "outer_parent_transcript_source_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-parent-statement-source",
        .description = "Run the authenticated two-child parent statement source tests",
        .root = "outer_parent_statement_source_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-binary-nonfri",
        .description = "Run only the binary-parent rows 0 through 17 and row 35 bundle",
        .root = "binary_pair_nonfri_outer_bundle_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-binary-fri",
        .description = "Run only the binary-parent rows 18 through 34 authority",
        .root = "binary_fri_outer_source_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-riscv-recursion-binary-fri-outer-bundle-v2",
        .description = "Run the binary-pair V2 rows 18 through 34 shared-provider gates",
        .root = "binary_fri_outer_bundle_v2_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{
            "V2 rows 18 through 34 bind",
            "native schedule receipt completes",
            "V2 bundle public contract",
            "V2 binary-pair owner",
        },
        .minimum = 4,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-binary-fri-row18",
        .description = "Run only row 18/19 committed-layout and composition custody",
        .root = "binary_fri_outer_source_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"R-015 binary FRI rows 18--19 use the admitted composition graph"},
        .minimum = 1,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-binary-closure",
        .description = "Run only the binary-parent all-row global LogUp closure",
        .root = "binary_global_closure_outer_source_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-air-edit",
        .description = "Run only named R-012 recursion tests for the shortest edit loop",
        .root = "recursion_air_core_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"R-012"},
        .minimum = 1,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-air-row18",
        .description = "Run only row-18 VM AIR composition-input identity and witness tests",
        .root = "recursion_air_core_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"R-012 VM AIR composition"},
        .minimum = 1,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-temporal-packed-relation",
        .description = "Run only the temporal V2 packed relation-challenge ABI gate",
        .root = "recursion_air_core_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{"temporal packed relation-challenge V2"},
        .minimum = 1,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-air-roster",
        .description = "Run only universal recursion inventory and manifest pin tests",
        .root = "recursion_air_core_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{
            "R-012 recursion typed-AIR inventory",
            "R-012 universal manifest",
        },
        .minimum = 2,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-air-core",
        .description = "Run recursion-local typed-AIR tests without shared VM-provider bridges",
        .root = "recursion_air_core_test_root.zig",
        .imports_prover_engine = true,
    });
    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-recursion-air",
        .description = "Run recursion-local typed-AIR compiler and witness tests",
        .root = "recursion_air_test_root.zig",
        .imports_prover_engine = true,
    });
}

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
    imports_prover_engine: bool = false,
    imports_typed_air_artifacts: bool = false,
    filters: []const []const u8 = &.{},
    minimum: usize = 0,
};

fn addFocusedTests(
    b: *std.Build,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    prover_api: *std.Build.Module,
    postcard: *std.Build.Module,
    typed_air_artifacts: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    spec: FocusedTest,
) void {
    const root = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", core);
    root.addImport("stwo_prover_api", prover_api);
    root.addImport("interop_postcard", postcard);
    if (spec.imports_prover_engine)
        root.addImport("stwo_prover_engine", prover);
    if (spec.imports_typed_air_artifacts)
        root.addImport("typed_air_artifacts", typed_air_artifacts);
    const tests = b.addTest(.{ .root_module = root, .filters = spec.filters });
    const dependency = if (check_only)
        &tests.step
    else blk: {
        const run = b.addRunArtifact(tests);
        break :blk if (spec.minimum == 0)
            &run.step
        else
            TestCountFloor.add(b, run, spec.minimum);
    };
    b.step(spec.step, spec.description).dependOn(dependency);
}

/// Turns "the binary lost its tests" from a zero exit into a named failure.
///
/// Deliberately duplicated rather than shared with
/// `build_support/products/riscv_test_filter.zig`: this package builds
/// standalone, so it cannot import the repository's build support, and the
/// product gate's floor cannot cover a lane this build file owns.
const TestCountFloor = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    minimum: usize,

    fn add(b: *std.Build, run: *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        const floor = b.allocator.create(TestCountFloor) catch @panic("out of memory");
        floor.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "stwo_riscv_frontend test count floor",
                .owner = b,
                .makeFn = make,
            }),
            .run = run,
            .minimum = minimum,
        };
        floor.step.dependOn(&run.step);
        return &floor.step;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const floor: *TestCountFloor = @fieldParentPtr("step", step);
        const metadata = floor.run.cached_test_metadata orelse return step.fail(
            "the run reported no test names, so the package's test count could not be verified",
            .{},
        );
        if (metadata.names.len >= floor.minimum) return;
        return step.fail(
            \\this package compiled {d} tests; its own step requires at least {d}.
            \\  Zig collects a test only from a file it analysed, so a file that fell out of
            \\  test_inventory.zig is compiled by nothing and still reports green. Restore the
            \\  import, or move `test_floor` in this build file deliberately.
        , .{ metadata.names.len, floor.minimum });
    }
};
