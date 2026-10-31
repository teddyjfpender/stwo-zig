//! Fresh transcript rules for the concrete thin CPU. Shared FUNCTION challenges
//! enter only through the complete-manifest resume, never an arbitrary alpha.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const Mat = @import("cpu_materials.zig");
const Sources = @import("cpu_sources.zig");
const W = air.word16_cpu;
pub const P = air.protocol;
pub const Draw = struct { cpu: W.lookup.Challenges, and_: air.providers.tables.Challenges };
pub fn mixLocal(channel: *P.Channel, materials: *const Mat.Materials, public: W.public.Public) !void {
    if (materials.geometry.mode != .local_binary) return error.ExpectedClosedThinCpuMaterials;
    P.config().mixInto(channel);
    channel.mixU32s(&.{ 0x57313643, 1, @intFromEnum(materials.geometry.mode), materials.geometry.cpu_log, materials.geometry.binary_log, 44, 56, 16, 6, 13, 24 });
    mixDigest(channel, materials.program.identity);
    mixDigest(channel, try W.public.digest(public, materials.geometry.cpu_log));
}
pub fn mixDigest(channel: *P.Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn drawLocal(channel: *P.Channel, shared: ?air.word16_v1.function_bus.Challenges) Draw {
    var result: Draw = undefined;
    channel.mixU32s(&.{ 0x57313643, 0x52454736, 1 });
    result.cpu.register.offset = channel.drawSecureFelt();
    for (&result.cpu.register.coefficients) |*value| value.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x57313643, 0x524f4d31, 16 });
    result.cpu.rom.offset = channel.drawSecureFelt();
    for (&result.cpu.rom.coefficients) |*value| value.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x57313643, 0x55313600, 16 });
    result.cpu.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x57313643, 0x55303800, 8 });
    result.cpu.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    if (shared) |function| {
        result.cpu.function = function;
        result.and_ = .{ .offset = W.public.literal(air.evaluation.Q, 0), .coefficients = @splat(air.evaluation.Q.zero()) };
    } else {
        channel.mixU32s(&.{ 0x57313643, 0x46554e43, 13 });
        result.cpu.function.offset = channel.drawSecureFelt();
        for (&result.cpu.function.coefficients) |*value| value.* = channel.drawSecureFelt();
        channel.mixU32s(&.{ 0x57313643, 0x414e4438, 3 });
        result.and_ = air.providers.tables.Challenges.draw(channel);
    }
    return result;
}
pub fn mixClaims(channel: *P.Channel, claims: Sources.Claims) void {
    const values = claims.values();
    channel.mixFelts(&values);
}
