//! Ethereum statement product. Compatibility names share these component modules.
pub const frontend = @import("ethereum_frontend_component");
pub const runner = frontend.runner;
pub const prover = frontend.prover_mod;
pub const statement = frontend.air.guest_precompile.ethereum_statement;
pub const cpu = @import("ethereum_cpu_component");
pub const cuda = @import("ethereum_cuda_component");

test "api signature: Ethereum product exposes its six owning domains" {
    const std = @import("std");
    try std.testing.expect(runner == frontend.runner);
    try std.testing.expect(prover == frontend.prover_mod);
    try std.testing.expect(statement == frontend.air.guest_precompile.ethereum_statement);
    try std.testing.expect(@TypeOf(frontend.proveEthereumWithEngine) == @TypeOf(prover.proveEthereumWithEngine));
}

test "api invariant: legacy exports share canonical components and records" {
    const std = @import("std");
    const legacy_frontend = @import("legacy_riscv_frontend");
    const neutral_frontend = @import("stwo_riscv_frontend");
    const legacy_cpu = @import("legacy_riscv_cpu_integration");
    try std.testing.expect(frontend == legacy_frontend);
    try std.testing.expect(cpu == legacy_cpu);
    try std.testing.expect(frontend.Cpu == legacy_frontend.Cpu and frontend.Cpu == neutral_frontend.Cpu);
    try std.testing.expect(frontend.Memory == legacy_frontend.Memory and frontend.Memory == neutral_frontend.Memory);
    try std.testing.expect(frontend.HostInterface == legacy_frontend.HostInterface and frontend.HostInterface == neutral_frontend.HostInterface);
    try std.testing.expect(frontend.runner.trace.TraceRow == legacy_frontend.runner.trace.TraceRow);
    try std.testing.expect(cpu.rv64_proof_artifact_support == legacy_cpu.rv64_proof_artifact_support);
}

test {
    _ = @import("tests/shared_bindings_test.zig");
}
