//! Research-only base narrow-memory Poseidon shard proof/benchmark wiring.

const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const test_filter = @import("riscv_test_filter.zig");

pub fn add(context: anytype, product: graph.Product, test_context: riscv_cpu_tests.Context) void {
    const tests = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/memory_provider_shard_proof_test.zig",
        &.{
            "base narrow-memory provider log4 proves fresh and retention preserves identity",
            "base narrow-memory provider log8 proves and fresh verifier binds two QM31 claims",
            "real caller plus three log4 provider shards freshly verify and close",
            "real caller plus log8 provider shard freshly verify and close",
            "ordered provider V2 log4 proof rejects endpoint range and order mutations",
            "full RISC-V plus ordered log4 providers freshly verify and close",
        },
    );
    context.b.step(
        "test-riscv-memory-provider-shard",
        "Prove and freshly verify research-only base Poseidon provider shards",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = tests,
        .minimum = 6,
    }}));

    const role_product = riscv_cpu_modules.roleProduct(product, .benchmark);
    const root = graph.create(context.b, .{
        .product = role_product,
        .root_source_file = "src/integrations/riscv_cpu/memory_provider_shard_benchmark.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        context.b,
        context.protocol,
        role_product,
        context.target,
        context.optimize,
        root,
    );
    root.addOptions(
        "build_identity",
        graph_identity.buildOptions(context.b, context.identity),
    );
    const executable = context.b.addExecutable(.{
        .name = "riscv-memory-provider-shard-log18",
        .root_module = root,
    });
    const install = context.b.addInstallArtifact(executable, .{});
    context.b.step(
        "riscv-memory-provider-shard-log18",
        "Compile the research log18 provider benchmark boundary without running it",
    ).dependOn(&install.step);
}
