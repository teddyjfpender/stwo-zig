//! Focused proof-level gate for the append-only degree-six Poseidon candidate.

const graph = @import("../graph/modules.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const test_filter = @import("riscv_test_filter.zig");

pub fn add(context: anytype, product: graph.Product, test_context: riscv_cpu_tests.Context) void {
    _ = product;
    const tests = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/degree_bounded_poseidon_proof_test.zig",
        &.{
            "degree-six Poseidon candidate proves and cold fresh-verifies at quotient plus three",
            "degree-six Poseidon candidate recomputes discarded coefficients with exact proof parity",
        },
    );
    context.b.step(
        "test-riscv-degree-bounded-poseidon-proof",
        "Prove and cold fresh-verify the degree-six Poseidon candidate",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = tests,
        .minimum = 2,
    }}));

    const benchmark = riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/integrations/riscv_cpu/degree_bounded_poseidon_proof_test.zig",
        &.{"degree-six Poseidon log16 retained-call A B benchmark"},
    );
    context.b.step(
        "benchmark-riscv-degree-bounded-poseidon",
        "Benchmark legacy 445-column versus degree-six 161-column Poseidon proofs",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = benchmark,
        .minimum = 1,
    }}));
}
