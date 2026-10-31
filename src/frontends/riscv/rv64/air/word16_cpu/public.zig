//! Public instance data. Fixed setup depends only on immutable program and
//! geometry; these values are mixed afresh and never become fixed columns.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
pub const Public = struct {
    steps: u32,
    initial_pc: u64,
    final_pc: u64,
    initial_registers: [32]u64,
    final_registers: [32]u64,
    register_clocks: [32]u32,
    pub fn validate(self: Public, cpu_log: u32) !void {
        if (cpu_log < L.MIN_LOG or cpu_log > L.MAX_LOG or self.steps == 0 or self.steps >= @as(u32, 1) << @intCast(cpu_log) or self.initial_pc & 3 != 0 or self.final_pc & 3 != 0 or self.initial_registers[0] != 0 or self.final_registers[0] != 0 or self.register_clocks[0] != 0) return error.InvalidWord16CpuStatement;
        for (self.register_clocks) |clock| if (clock > 4 * self.steps) return error.InvalidWord16CpuClock;
    }
};
pub fn literal(comptime F: type, value: u32) F {
    return if (F == core.fields.m31.M31) F.fromCanonical(value) else E.qFor(F, value);
}
pub fn word(comptime F: type, value: u64) [4]F {
    var result: [4]F = undefined;
    for (&result, 0..) |*limb, i| {
        const part: u16 = @truncate(value >> @as(u6, @intCast(16 * i)));
        limb.* = literal(F, part);
    }
    return result;
}
pub const Claims = struct {
    register: E.Q,
    function: E.Q,
    rom: E.Q,
    range16: E.Q,
    range8: E.Q,
    pub fn validate(self: Claims) !void {
        inline for (std.meta.fields(Claims)) |field| for (@field(self, field.name).toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
    }
};

/// Full statement fingerprint, including local-clock reset-v1 semantics. The
/// immutable program/geometry schema is separately bound by the setup/manifest.
pub fn digest(public: Public, cpu_log: u32) ![32]u8 {
    try public.validate(cpu_log);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-rv64/word16-register-binary-statement/v1/reset-clocks-zero\x00");
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], cpu_log, .little);
    hash.update(bytes[0..4]);
    std.mem.writeInt(u32, bytes[0..4], public.steps, .little);
    hash.update(bytes[0..4]);
    for ([_]u64{ public.initial_pc, public.final_pc }) |value| {
        std.mem.writeInt(u64, &bytes, value, .little);
        hash.update(&bytes);
    }
    for (public.initial_registers) |value| {
        std.mem.writeInt(u64, &bytes, value, .little);
        hash.update(&bytes);
    }
    for (public.final_registers) |value| {
        std.mem.writeInt(u64, &bytes, value, .little);
        hash.update(&bytes);
    }
    for (public.register_clocks) |value| {
        std.mem.writeInt(u32, bytes[0..4], value, .little);
        hash.update(bytes[0..4]);
    }
    return hash.finalResult();
}
