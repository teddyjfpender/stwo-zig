//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("stwo_riscv_rv64");

test "C3 canonical API identity: RV64 machine memory and session types" {
    try std.testing.expect(api.machine.Cpu == @import("stwo_riscv_rv64").machine.Cpu);
    try std.testing.expect(api.memory.Memory == @import("stwo_riscv_rv64").memory.Memory);
    try std.testing.expect(api.session.Session == @import("stwo_riscv_rv64").session.Session);
    const services = @import("../ethereum_services/session.zig");
    try std.testing.expect(api.arith256_mod == services.arith256);
    try std.testing.expect(api.secp256k1_rcb == services.secp256k1);
    try std.testing.expect(api.sha256_compression == services.sha256);
    const calls = api.service_calls;
    try std.testing.expect(calls == @import("stwo_riscv_rv64").service_calls);
    try std.testing.expect(services.SecpCall == calls.SecpCall);
    try std.testing.expect(services.Sha256Call == calls.Sha256Call);
    try std.testing.expect(services.Arith256ModCall == calls.Arith256ModCall);
    try std.testing.expect(services.CurveCall == calls.CurveCall);
    try std.testing.expect(services.Event == calls.Event);
}
