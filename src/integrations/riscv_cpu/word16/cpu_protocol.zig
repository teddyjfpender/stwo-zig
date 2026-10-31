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
    air.word16_v1.binary_lookup.encoding.mix(channel);
    if (materials.geometry.profile == .binary_v1) {
        channel.mixU32s(&.{ 0x57313643, 1, @intFromEnum(materials.geometry.mode), materials.geometry.cpu_log, materials.geometry.binary_log, 44, 56, 16, 6, 13, 24 });
    } else {
        channel.mixU32s(&.{ 0x57313643, 3, @intFromEnum(materials.geometry.mode), materials.geometry.cpu_log, materials.geometry.binary_log, materials.geometry.alu_log, 46, 56, 23, 6, 13, 24, air.word16_v1.alu_experiment.lookup.MAIN, 52, 20 });
        air.word16_v1.alu_experiment.equations.encoding.mix(channel);
    }
    mixDigest(channel, materials.program.identity);
    mixDigest(channel, try W.public.digest(public, materials.geometry.cpu_log));
}
pub fn mixDigest(channel: *P.Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn drawLocal(channel: *P.Channel, shared: ?air.word16_v1.function_bus.Challenges) Draw {
    return drawProfile(channel, shared, .binary_v1);
}
pub fn drawProfile(channel: *P.Channel, shared: ?air.word16_v1.function_bus.Challenges, profile: W.profile.Profile) Draw {
    var result: Draw = undefined;
    channel.mixU32s(&.{ 0x57313643, 0x52454736, 1 });
    result.cpu.register.offset = channel.drawSecureFelt();
    for (&result.cpu.register.coefficients) |*value| value.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x57313643, 0x524f4d31, @intCast(W.profile.romCount(profile)) });
    result.cpu.rom.offset = channel.drawSecureFelt();
    for (&result.cpu.rom.coefficients) |*value| value.* = channel.drawSecureFelt();
    result.cpu.rom.control_coefficients = @splat(air.evaluation.Q.zero());
    if (profile == .alu_binary_v2) for (&result.cpu.rom.control_coefficients) |*value| {
        value.* = channel.drawSecureFelt();
    };
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
    mixClaimsProfile(channel, claims, .binary_v1, .{ .range16 = air.evaluation.Q.zero(), .function = air.evaluation.Q.zero() });
}
pub fn mixClaimsProfile(channel: *P.Channel, claims: Sources.Claims, profile: W.profile.Profile, alu: air.word16_v1.alu_experiment.lookup.Claims) void {
    const values = claims.values();
    channel.mixFelts(&values);
    if (profile == .alu_binary_v2) channel.mixFelts(&.{ alu.range16, alu.function });
}
