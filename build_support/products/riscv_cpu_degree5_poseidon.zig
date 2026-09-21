//! Focused proof-level gate for the append-only degree-five Poseidon candidate.

const graph = @import("../graph/modules.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const test_filter = @import("riscv_test_filter.zig");

pub fn add(context: anytype, product: graph.Product, test_context: riscv_cpu_tests.Context) void {
    _ = product;
    const tests = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/degree5_poseidon_proof_test.zig",
        &.{
            "degree-five Poseidon candidate proves and cold fresh-verifies at quotient plus two",
            "degree-five Poseidon candidate recomputes discarded coefficients with exact proof parity",
        },
    );
    context.b.step(
        "test-riscv-degree5-poseidon-proof",
        "Prove and cold fresh-verify the degree-five Poseidon candidate",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = tests,
        .minimum = 2,
    }}));

    const provider = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/degree5_provider_proof_v1_test.zig",
        &.{
            "degree-five retained provider program and N4 profile are cold and fail closed",
            "degree-five retained provider log16 postcard cold fresh verifies",
        },
    );
    context.b.step(
        "test-riscv-degree5-provider-proof",
        "Prove and cold fresh-verify one retained degree-five provider shard",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = provider,
        .minimum = 2,
    }}));

    const benchmark = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/degree5_poseidon_proof_test.zig",
        &.{"degree-five Poseidon log16 retained-call A B benchmark"},
    );
    context.b.step(
        "benchmark-riscv-degree5-poseidon",
        "Benchmark legacy 445-column versus degree-five 239-column Poseidon proofs",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = benchmark,
        .minimum = 1,
    }}));
}
