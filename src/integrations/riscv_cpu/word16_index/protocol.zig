//! Fresh closed-proof transcript, no extra representation runtime enum.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const P = air.protocol;
const Mat = @import("materials.zig");
const S = @import("sources.zig");
pub fn mix(channel: *P.Channel, materials: *const Mat.Materials, state: air.word16_cpu.public.Public, pairs: []const Mat.Pair) !void {
    const endpoints = try materials.validatePublic(state, pairs);
    P.config().mixInto(channel);
    air.word16_v1.binary_lookup.encoding.mix(channel);
    channel.mixU32s(&.{ 0x49445843, 2, materials.geometry.cpu_log, materials.geometry.alu_log, materials.geometry.binary_log, 40, 56, 17, 5, 49 });
    air.word16_v1.alu_experiment.equations.encoding.mix(channel);
    mixDigest(channel, materials.authority.identity);
    mixDigest(channel, try air.word16_cpu.public.digest(state, materials.geometry.cpu_log));
    channel.mixU32s(&.{ endpoints.initial_id, endpoints.final_id });
    channel.mixU64(pairs.len);
    for (pairs) |pair| {
        channel.mixU64(pair.id);
        channel.mixU64(pair.pc);
    }
}
fn mixDigest(channel: *P.Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn draw(channel: *P.Channel) S.Challenges {
    var ch: S.Challenges = undefined;
    ch.data.rom = .{ .offset = air.evaluation.Q.zero(), .coefficients = @splat(air.evaluation.Q.zero()) };
    channel.mixU32s(&.{ 0x49445843, 0x52454736 });
    ch.data.register.offset = channel.drawSecureFelt();
    for (&ch.data.register.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x49445843, 0x524f4d31, 17 });
    ch.rom.offset = channel.drawSecureFelt();
    for (&ch.rom.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x49445843, 0x4d415035, 5 });
    ch.map.offset = channel.drawSecureFelt();
    for (&ch.map.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x49445843, 16 });
    ch.data.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x49445843, 8 });
    ch.data.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x49445843, 13 });
    ch.data.function.offset = channel.drawSecureFelt();
    for (&ch.data.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x49445843, 0x414e4438 });
    ch.and_ = air.providers.tables.Challenges.draw(channel);
    return ch;
}
pub fn mixClaims(channel: *P.Channel, claims: S.Claims) void {
    const fields = claims.values();
    channel.mixFelts(&fields);
}
