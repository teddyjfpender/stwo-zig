//! Legacy command aliases kept outside focused and aggregate product graphs.

const std = @import("std");
const graph = @import("../graph/modules.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};

pub fn addProducts(context: Context) void {
    const b = context.b;
    const protocol = graph.createPrivateProtocolModules(b, context.target, context.optimize);
    const stwo = graph.create(b, .{
        .product = .{
            .name = "stwo-compatibility-tools",
            .frontend = .aggregate,
            .backend = .cpu,
            .role = .@"test",
        },
        .root_source_file = "src/stwo.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(stwo);
    const runner = consumer(context, protocol, "src/prover/native/runner.zig");
    runner.addImport("stwo", stwo);
    runner.addImport("native_resource_admission", consumer(
        context,
        protocol,
        "src/prover/native/resource_admission.zig",
    ));

    const interop = consumer(context, protocol, "src/tools/interop/main.zig");
    interop.addImport("stwo", stwo);
    addExecutable(context, interop, "interop_cli", "interop-cli", "Build the proof interoperability CLI", true);

    const cairo_input = consumer(context, protocol, "src/tools/cairo/input_inspector.zig");
    cairo_input.addImport("stwo", stwo);
    addExecutable(context, cairo_input, "cairo-input", "cairo-input", "Build adapted Cairo input inspector", false);

    const cairo_composition = consumer(
        context,
        protocol,
        "src/frontends/cairo/witness/composition_bundle.zig",
    );
    const cairo_air_bundle =
        consumer(context, protocol, "src/tools/cairo/air_bundle_inspector.zig");
    cairo_air_bundle.addImport("cairo_composition_bundle", cairo_composition);
    addExecutable(
        context,
        cairo_air_bundle,
        "cairo-air-bundle-inspector",
        "cairo-air-bundle-inspector",
        "Build official Cairo AIR bundle inspector",
        false,
    );

    const cairo_frontend = consumer(context, protocol, "src/frontends/cairo/mod.zig");
    const cairo_test_root = consumer(context, protocol, "src/frontends/cairo/tests/mod.zig");
    cairo_test_root.addImport("cairo_frontend", cairo_frontend);
    const cairo_filters: []const []const u8 = if (b.option(
        []const u8,
        "cairo-test-filter",
        "Compile and run Cairo tests whose names contain this text",
    )) |filter|
        b.allocator.dupe([]const u8, &.{filter}) catch @panic("out of memory")
    else
        &.{};
    const cairo_tests = context.b.addTest(.{
        .root_module = cairo_test_root,
        .filters = cairo_filters,
    });
    const run_cairo_tests = context.b.addRunArtifact(cairo_tests);
    context.b.step(
        "test-cairo-frontend",
        "Run focused backend-neutral Cairo conformance tests",
    ).dependOn(&run_cairo_tests.step);

    const cairo_cpu_air_test_root = consumer(
        context,
        protocol,
        "src/tests/cairo/cpu_air_test.zig",
    );
    cairo_cpu_air_test_root.addImport("stwo", stwo);
    const cairo_cpu_air_tests = context.b.addTest(.{
        .root_module = cairo_cpu_air_test_root,
    });
    const run_cairo_cpu_air_tests = context.b.addRunArtifact(cairo_cpu_air_tests);
    context.b.step(
        "test-cairo-cpu-air",
        "Run Cairo CPU AIR integration tests",
    ).dependOn(&run_cairo_cpu_air_tests.step);

    const cairo_cpu_proof_test_root = consumer(
        context,
        protocol,
        "src/tests/cairo/cpu_proof_test.zig",
    );
    cairo_cpu_proof_test_root.addImport("stwo", stwo);
    const cairo_cpu_proof_tests = context.b.addTest(.{
        .root_module = cairo_cpu_proof_test_root,
    });
    const run_cairo_cpu_proof_tests = context.b.addRunArtifact(cairo_cpu_proof_tests);
    context.b.step(
        "test-cairo-cpu-proof",
        "Run the complete official Cairo CPU proof gate",
    ).dependOn(&run_cairo_cpu_proof_tests.step);

    const opcode = consumer(context, protocol, "src/tools/riscv_opcode_manifest/main.zig");
    opcode.addImport("stwo", stwo);
    const opcode_cli = b.addExecutable(.{ .name = "riscv-opcode-manifest", .root_module = opcode });
    const dump = b.addRunArtifact(opcode_cli);
    dump.addArg("dump");
    b.step(
        "riscv-opcode-manifest",
        "Dump the canonical Stark-V opcode and proof-family policy as JSON",
    ).dependOn(&dump.step);
    const check = b.addRunArtifact(opcode_cli);
    check.addArg("check");
    b.step(
        "riscv-opcode-manifest-check",
        "Validate exact Stark-V opcode IDs and execution-only classifications",
    ).dependOn(&check.step);

    const riscv_bench = consumer(context, protocol, "src/riscv_bench_cli.zig");
    addExecutable(context, riscv_bench, "riscv-bench", "riscv-bench", "Build RISC-V benchmark CLI", false);

    const native_bench = consumer(context, protocol, "src/tools/native_proof_bench/cpu.zig");
    native_bench.addImport("stwo", stwo);
    native_bench.addImport("native_proof_runner", runner);
    addExecutable(
        context,
        native_bench,
        "native-proof-bench-cpu",
        "native-proof-bench-cpu",
        "Build the machine-readable native CPU full-proof benchmark with SIMD hot paths",
        false,
    );
}

fn consumer(
    context: Context,
    protocol: graph.ProtocolModules,
    source: []const u8,
) *std.Build.Module {
    const module = context.b.createModule(.{
        .root_source_file = context.b.path(source),
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(module);
    return module;
}

fn addExecutable(
    context: Context,
    module: *std.Build.Module,
    executable_name: []const u8,
    step_name: []const u8,
    description: []const u8,
    link_libc: bool,
) void {
    const executable = context.b.addExecutable(.{ .name = executable_name, .root_module = module });
    if (link_libc) executable.linkLibC();
    const install = context.b.addInstallArtifact(executable, .{});
    context.b.step(step_name, description).dependOn(&install.step);
}
