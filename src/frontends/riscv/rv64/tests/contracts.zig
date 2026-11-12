//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: RV64 machine memory and session types" {
    try std.testing.expect(api.machine.Cpu == @import("../machine.zig").Cpu);
    try std.testing.expect(api.memory.Memory == @import("../memory.zig").Memory);
    try std.testing.expect(api.session.Session == @import("../session.zig").Session);
    const services = api.execution.ethereum_services;
    try std.testing.expect(api.arith256_mod == services.arith256);
    try std.testing.expect(api.secp256k1_rcb == services.secp256k1);
    try std.testing.expect(api.sha256_compression == services.sha256);
    const calls = @import("../services/call_abi.zig");
    try std.testing.expect(services.SecpCall == calls.SecpCall);
    try std.testing.expect(services.Sha256Call == calls.Sha256Call);
    try std.testing.expect(services.Arith256ModCall == calls.Arith256ModCall);
    try std.testing.expect(services.CurveCall == calls.CurveCall);
    try std.testing.expect(services.Event == calls.Event);
}
