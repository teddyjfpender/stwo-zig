const std = @import("std");
const metal_backend = @import("../backends/metal.zig");
const graph = @import("../graph/modules.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    stwo_module: *std.Build.Module,
    cpu_backend: *std.Build.Module,
    metal_backend: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    protocol: graph.ProtocolModules,
    test_step: ?*std.Build.Step,
};

pub fn addProducts(context: Context) void {
    const b = context.b;
    const target = context.target;
    const stwo_module = context.stwo_module;
    const test_step = context.test_step;

    if (!metal_backend.supports(target.result.os.tag)) {
        addUnavailableProducts(b);
        return;
    }

    const metal_arena_plan_module = consumer(context, "src/metal_arena_plan_cli.zig");
    metal_arena_plan_module.addImport("stwo", stwo_module);
    const metal_arena_plan = b.addExecutable(.{
        .name = "metal-arena-plan",
        .root_module = metal_arena_plan_module,
    });
    metal_backend.linkRuntime(b, metal_arena_plan);
    const install_metal_arena_plan = b.addInstallArtifact(metal_arena_plan, .{});
    const metal_arena_plan_step = b.step("metal-arena-plan", "Build sparse Metal arena planner");
    metal_arena_plan_step.dependOn(&install_metal_arena_plan.step);

    const metal_arena_session_module = consumer(context, "src/tools/metal_prover_session/main.zig");
    metal_arena_session_module.addImport("stwo", stwo_module);
    metal_arena_session_module.addImport("one_shot", metal_arena_plan_module);
    const metal_arena_session = b.addExecutable(.{
        .name = "metal-arena-session",
        .root_module = metal_arena_session_module,
    });
    metal_backend.linkFrameworks(metal_arena_session);
    const install_metal_arena_session = b.addInstallArtifact(metal_arena_session, .{});
    const metal_arena_session_step = b.step(
        "metal-arena-session",
        "Build persistent Metal SN PIE prover session",
    );
    metal_arena_session_step.dependOn(&install_metal_arena_session.step);

    const metal_arena_session_test_module = consumer(context, "src/tools/metal_prover_session/main.zig");
    metal_arena_session_test_module.addImport("stwo", stwo_module);
    metal_arena_session_test_module.addImport("one_shot", metal_arena_plan_module);
    const metal_arena_session_tests = b.addTest(.{
        .root_module = metal_arena_session_test_module,
    });
    metal_backend.linkFrameworks(metal_arena_session_tests);
    const run_metal_arena_session_tests = b.addRunArtifact(metal_arena_session_tests);
    const metal_arena_session_test_step = b.step(
        "metal-prover-session-test",
        "Run persistent Metal prover-session unit tests",
    );
    metal_arena_session_test_step.dependOn(&run_metal_arena_session_tests.step);
    if (test_step) |aggregate_test| aggregate_test.dependOn(&run_metal_arena_session_tests.step);

    const metal_recovery_bench_module = consumer(context, "src/bench/metal/recovery.zig");
    metal_recovery_bench_module.addImport("stwo", stwo_module);
    const metal_recovery_bench = b.addExecutable(.{
        .name = "metal-recovery-bench",
        .root_module = metal_recovery_bench_module,
    });
    const install_metal_recovery_bench = b.addInstallArtifact(metal_recovery_bench, .{});
    const metal_recovery_bench_step = b.step("metal-recovery-bench", "Build Metal recovery storage benchmark");
    metal_recovery_bench_step.dependOn(&install_metal_recovery_bench.step);

    const metal_ec_op_bench_module = consumer(context, "src/bench/metal/ec_op.zig");
    metal_ec_op_bench_module.addImport("stwo", stwo_module);
    const metal_ec_op_bench = b.addExecutable(.{
        .name = "metal-ec-op-bench",
        .root_module = metal_ec_op_bench_module,
    });
    metal_backend.linkRuntime(b, metal_ec_op_bench);
    const install_metal_ec_op_bench = b.addInstallArtifact(metal_ec_op_bench, .{});
    const metal_ec_op_bench_step = b.step("metal-ec-op-bench", "Build resident Metal EC-op benchmark");
    metal_ec_op_bench_step.dependOn(&install_metal_ec_op_bench.step);

    const metal_compact_bench_module = consumer(context, "src/bench/metal/compaction.zig");
    metal_compact_bench_module.addImport("stwo", stwo_module);
    const metal_compact_bench = b.addExecutable(.{
        .name = "metal-compact-bench",
        .root_module = metal_compact_bench_module,
    });
    metal_backend.linkRuntime(b, metal_compact_bench);
    const install_metal_compact_bench = b.addInstallArtifact(metal_compact_bench, .{});
    const metal_compact_bench_step = b.step("metal-compact-bench", "Build resident Metal compaction benchmark");
    metal_compact_bench_step.dependOn(&install_metal_compact_bench.step);

    const cairo_streaming_commitment_bench_module = consumer(
        context,
        "src/bench/cairo_metal/streaming_commitment.zig",
    );
    cairo_streaming_commitment_bench_module.addImport("stwo", stwo_module);
    const cairo_streaming_commitment_bench = b.addExecutable(.{
        .name = "cairo-streaming-commitment-bench",
        .root_module = cairo_streaming_commitment_bench_module,
    });
    metal_backend.linkRuntime(b, cairo_streaming_commitment_bench);
    const install_cairo_streaming_commitment_bench = b.addInstallArtifact(cairo_streaming_commitment_bench, .{});
    const cairo_streaming_commitment_bench_step = b.step(
        "cairo-streaming-commitment-bench",
        "Build bounded production-callsite Cairo Metal commitment benchmark",
    );
    cairo_streaming_commitment_bench_step.dependOn(&install_cairo_streaming_commitment_bench.step);

    const cairo_streaming_commitment_test_module = consumer(
        context,
        "src/bench/cairo_metal/streaming_commitment.zig",
    );
    cairo_streaming_commitment_test_module.addImport("stwo", stwo_module);
    const cairo_streaming_commitment_tests = b.addTest(.{ .root_module = cairo_streaming_commitment_test_module });
    metal_backend.linkRuntime(b, cairo_streaming_commitment_tests);
    const run_cairo_streaming_commitment_tests = b.addRunArtifact(cairo_streaming_commitment_tests);
    const cairo_streaming_commitment_test_step = b.step(
        "cairo-streaming-commitment-test",
        "Run bounded production-callsite Cairo Metal commitment parity test",
    );
    cairo_streaming_commitment_test_step.dependOn(&run_cairo_streaming_commitment_tests.step);

    const metal_eval_prepare_module = consumer(context, "src/tools/cairo_metal_codegen/eval_prepare.zig");
    metal_eval_prepare_module.addImport("stwo", stwo_module);
    const metal_eval_prepare = b.addExecutable(.{
        .name = "metal-eval-prepare",
        .root_module = metal_eval_prepare_module,
    });
    metal_backend.linkRuntime(b, metal_eval_prepare);
    const install_metal_eval_prepare = b.addInstallArtifact(metal_eval_prepare, .{});
    const metal_eval_prepare_step = b.step("metal-eval-prepare", "Compile exact SN Cairo AIR programs for Metal");
    metal_eval_prepare_step.dependOn(&install_metal_eval_prepare.step);

    const metal_eval_source_module = consumer(context, "src/tools/cairo_metal_codegen/eval_source.zig");
    metal_eval_source_module.addImport("stwo", stwo_module);
    const metal_eval_source = b.addExecutable(.{
        .name = "metal-eval-source",
        .root_module = metal_eval_source_module,
    });
    const install_metal_eval_source = b.addInstallArtifact(metal_eval_source, .{});
    const metal_eval_source_step = b.step(
        "metal-eval-source",
        "Build the exact Cairo AIR Metal source generator",
    );
    metal_eval_source_step.dependOn(&install_metal_eval_source.step);

    const metal_witness_source_module = consumer(context, "src/tools/cairo_metal_codegen/witness_source.zig");
    metal_witness_source_module.addImport("stwo", stwo_module);
    const metal_witness_source = b.addExecutable(.{
        .name = "metal-witness-source",
        .root_module = metal_witness_source_module,
    });
    metal_backend.linkRuntime(b, metal_witness_source);
    const install_metal_witness_source = b.addInstallArtifact(metal_witness_source, .{});
    const metal_witness_source_step = b.step(
        "metal-witness-source",
        "Build the exact Cairo witness Metal source generator",
    );
    metal_witness_source_step.dependOn(&install_metal_witness_source.step);

    const metal_test_module = consumer(context, "src/tests.zig");
    metal_test_module.addImport("stwo_cpu_backend", context.cpu_backend);
    metal_test_module.addImport("stwo_metal_backend", context.metal_backend);
    metal_test_module.addImport("stwo_cairo_frontend", context.cairo_frontend);
    const metal_test_options = b.addOptions();
    metal_test_options.addOption(bool, "metal_only", true);
    metal_test_options.addOption(bool, "riscv_only", false);
    metal_test_options.addOption(bool, "riscv_exhaustive", false);
    metal_test_module.addOptions("test_options", metal_test_options);
    const metal_tests = b.addTest(.{
        .root_module = metal_test_module,
        .filters = &.{"metal:"},
    });
    metal_backend.linkRuntime(b, metal_tests);
    const run_metal_tests = b.addRunArtifact(metal_tests);
    const metal_test_step = b.step("metal-test", "Run resident Metal backend parity tests");
    metal_test_step.dependOn(&run_metal_tests.step);
    const metal_check_step = b.step(
        "metal-check",
        "Compile and link resident Metal backend tests without executing them",
    );
    metal_check_step.dependOn(&metal_tests.step);

    const metal_bench_module = consumer(context, "src/bench/metal/commitment.zig");
    metal_bench_module.addImport("stwo", stwo_module);
    const metal_bench = b.addExecutable(.{
        .name = "metal-bench",
        .root_module = metal_bench_module,
    });
    metal_backend.linkRuntime(b, metal_bench);
    const install_metal_bench = b.addInstallArtifact(metal_bench, .{});
    const metal_bench_step = b.step("metal-bench", "Build resident Metal commitment benchmark");
    metal_bench_step.dependOn(&install_metal_bench.step);
}

fn consumer(context: Context, root_source_file: []const u8) *std.Build.Module {
    const module = context.b.createModule(.{
        .root_source_file = context.b.path(root_source_file),
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    return module;
}

fn addUnavailableProducts(b: *std.Build) void {
    const reason = "legacy Metal tools require a macOS target and Apple Metal SDK";
    const failure = b.addFail(reason);
    inline for (.{
        "metal-arena-plan",
        "metal-arena-session",
        "metal-prover-session-test",
        "metal-recovery-bench",
        "metal-ec-op-bench",
        "metal-compact-bench",
        "cairo-streaming-commitment-bench",
        "cairo-streaming-commitment-test",
        "metal-eval-prepare",
        "metal-eval-source",
        "metal-witness-source",
        "metal-test",
        "metal-check",
        "metal-bench",
    }) |name| {
        const step = b.step(name, reason);
        step.dependOn(&failure.step);
    }
}
