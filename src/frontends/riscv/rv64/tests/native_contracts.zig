const std = @import("std");
const api = @import("../mod.zig");

test "C3 native API identity: RV64 machine memory and session types" {
    try std.testing.expect(api.machine.Cpu == @import("../machine.zig").Cpu);
    try std.testing.expect(api.memory.Memory == @import("../memory.zig").Memory);
    try std.testing.expect(api.session.Session == @import("../session.zig").Session);
    try std.testing.expect(api.service_calls == @import("../services/call_abi.zig"));
    try std.testing.expect(api.arith256_mod == @import("stwo_riscv_precompiles").primitives.arith256);
    try std.testing.expect(api.secp256k1_rcb == @import("stwo_riscv_precompiles").primitives.secp256k1);
    try std.testing.expect(api.sha256_compression == @import("stwo_riscv_precompiles").primitives.sha256);
}
