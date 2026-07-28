//! Opt-in aggregate SDK and CLI compatibility product.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const graph_identity = @import("../graph/identity.zig");
const identity_receipt = @import("../graph/identity/receipt.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const closure_gate = @import("../gates/product_closure.zig");
const prove_cli = @import("../prove_cli.zig");
const aggregate = @import("aggregate.zig");
const libraries = @import("libraries.zig");

pub fn addProduct(b: *std.Build, metal_enabled: bool) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    if (metal_enabled) metal.requireTarget(target.result) catch @panic(
        "-Daggregate-metal=true requires a macOS target and Apple Metal SDK",
    );
    const source_identity = prove_cli.resolveBuildIdentity(b);
    const runtime_identity: graph_identity.RuntimeHooks = if (metal_enabled)
        metal.sourceJitIdentity(b)
    else
        .{};
    const protocol = graph.createPrivateProtocolModules(b, target, optimize);
    const resource_admission = graph.create(b, .{
        .product = aggregate.product(metal_enabled),
        .root_source_file = "src/prover/native/resource_admission.zig",
        .target = target,
        .optimize = optimize,
    });
    const stwo = graph.create(b, .{
        .product = aggregate.product(metal_enabled),
        .root_source_file = if (metal_enabled)
            "src/stwo_aggregate_metal.zig"
        else
            "src/stwo_aggregate_cpu.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(stwo);
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        aggregate.product(metal_enabled),
        target,
        optimize,
        stwo,
    );
    const metal_backend = if (metal_enabled)
        graph.addMetalBackendImport(
            b,
            protocol,
            aggregate.product(true),
            target,
            optimize,
            cpu_backend,
            stwo,
        )
    else
        null;
    const riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        aggregate.product(metal_enabled),
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        b,
        protocol,
        aggregate.product(metal_enabled),
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const runner = libraries.consumer(b, protocol, .{
        .root_source_file = graph.source(
            b,
            "src/prover/native/runner.zig",
            target,
            optimize,
        ),
        .target = target,
        .optimize = optimize,
    });
    runner.addImport("stwo", stwo);
    runner.addImport("native_resource_admission", resource_admission);

    const aggregate_tests = libraries.consumer(b, protocol, .{
        .root_source_file = b.path(if (metal_enabled)
            "src/stwo_aggregate_metal.zig"
        else
            "src/stwo_aggregate_cpu.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        aggregate.product(metal_enabled),
        target,
        optimize,
        aggregate_tests,
    );
    aggregate_tests.addImport("stwo_cpu_backend", cpu_backend);
    _ = integration_graph.addRiscVCpuImport(
        b,
        protocol,
        aggregate.product(metal_enabled),
        target,
        optimize,
        cpu_backend,
        test_riscv_frontend,
        aggregate_tests,
    );
    if (metal_backend) |backend|
        aggregate_tests.addImport("stwo_metal_backend", backend);
    const tests = b.addTest(.{ .root_module = aggregate_tests });
    if (metal_enabled) metal.linkRuntime(b, tests);
    const test_step = b.step("test", "Run aggregate compatibility tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const runner_tests = b.addTest(.{
        .root_module = libraries.consumer(b, protocol, .{
            .root_source_file = graph.source(
                b,
                "src/prover/native/runner.zig",
                target,
                optimize,
            ),
            .target = target,
            .optimize = optimize,
        }),
    });
    runner_tests.root_module.addImport("stwo", stwo);
    runner_tests.root_module.addImport("native_resource_admission", resource_admission);
    test_step.dependOn(&b.addRunArtifact(runner_tests).step);

    const executable = prove_cli.addProduct(.{
        .b = b,
        .target = target,
        .optimize = optimize,
        .stwo_module = stwo,
        .native_proof_runner_module = runner,
        .native_resource_admission_module = resource_admission,
        .test_step = test_step,
        .identity = source_identity,
        .product = aggregate.product(metal_enabled),
        .runtime = runtime_identity,
        .metal_enabled = metal_enabled,
    });
    _ = identity_receipt.add(.{
        .b = b,
        .source = source_identity,
        .product = aggregate.product(metal_enabled),
        .target = target,
        .optimize = optimize,
        .artifact = executable.getEmittedBin(),
        .artifact_path = "bin/stwo-zig",
        .executable = true,
        .step_name = "identity-stwo-zig",
        .output_name = "stwo-zig.json",
        .runtime = runtime_identity,
    });
    const closure = closure_gate.addCheck(.{
        .b = b,
        .descriptor = aggregate.descriptorFor(metal_enabled),
        .binary = executable,
    });
    test_step.dependOn(&closure.step);
}
