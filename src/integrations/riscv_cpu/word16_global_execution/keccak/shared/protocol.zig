//! Typed inventory: CPU/bridge entries followed by bounded pure K truth entries.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const B = K.word16_bridge;
const P = @import("../../protocol.zig");
const R = @import("roster.zig");
pub const Expected = P.Expected;
pub const Manifest = P.Manifest;
pub const Request = @import("../execution.zig").Request;
pub const Mode = enum(u32) { single_v2 = 2, bounded_v3 = 3 };
/// Receiver-supplied bounded truth roster. Spans are consecutive, cover all CPU
/// call IDs exactly, and do not grant host call metadata any proof authority.
pub const Truth = struct { setup: *const R.TruthSetup, first_id: u32, calls: u32 };
pub const Shared = struct { ram: A.memory.closed_ram.types.RamChallenges, io: K.equations.Io };
pub fn firstCall(requests: []const Request, index: usize) !u32 {
    if (index > requests.len) return error.InvalidSharedTruthOrdinal;
    var first: u64 = 1;
    for (requests[0..index]) |r| first = try std.math.add(u64, first, r.calls);
    if (first >= core.fields.m31.Modulus) return error.KeccakLookupMassExceeded;
    return @intCast(first);
}
fn admitCpu(a: std.mem.Allocator, setups: []const *const R.CpuSetup, requests: []const Request, expected: Expected) !u32 {
    if (setups.len == 0 or setups.len >= 65535 or setups.len != requests.len) return error.InvalidSharedTruthInventory;
    const mats = try a.alloc(*const @import("../../../word16_execution/setup.zig").Materials, setups.len);
    defer a.free(mats);
    const rr = try a.alloc(P.Old.Request, setups.len);
    defer a.free(rr);
    var total: u64 = 0;
    var ram: u64 = 0;
    for (setups, requests, mats, rr) |s, r, *m, *old| {
        m.* = &s.materials;
        old.* = r.base;
        if (total >= core.fields.m31.Modulus - 1) return error.KeccakLookupMassExceeded;
        _ = try B.types.validateGeometry(r.calls, @intCast(1 + total), s.bridge_log);
        if (@as(u64, r.calls) + r.base.memory.ls_count > r.base.cpu.steps) return error.InvalidServiceCount;
        const mass16 = try std.math.add(u64, try s.materials.geometry.range16Mass(), 22 * (@as(u64, 1) << @intCast(s.bridge_log)));
        const mass8 = try std.math.add(u64, try s.materials.geometry.range8Mass(), 19 * (@as(u64, 1) << @intCast(s.bridge_log)));
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.SharedTruthRangeMassExceeded;
        total = try std.math.add(u64, total, r.calls);
        ram = try std.math.add(u64, ram, 2 * @as(u64, r.base.memory.ls_count) + 50 * @as(u64, r.calls));
    }
    try P.validateMaterials(mats, rr, expected);
    if (total > std.math.maxInt(u32)) return error.KeccakLookupMassExceeded;
    // IO is execution-wide even when each truth proof has local chi/xor draws.
    if (50 * total >= core.fields.m31.Modulus) return error.KeccakLookupMassExceeded;
    ram = try std.math.add(u64, ram, rr[0].memory.initial.len + rr[rr.len - 1].memory.terminal.len);
    if (ram >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
    return @intCast(total);
}
pub fn validateSpans(truths: []const Truth, calls: u32) !void {
    if (truths.len == 0 or truths.len > 65534) return error.InvalidSharedTruthInventory;
    var first: u64 = 1;
    for (truths) |t| {
        if (t.first_id != first or (t.calls == 0 and (truths.len != 1 or calls != 0))) return error.InvalidSharedTruthSpan;
        // Chi/xor challenges are LOCAL to this proof. Do not sum their mass
        // across independent local families; common IO mass is checked above.
        try K.layout.validateGeometry(t.calls, t.first_id, t.setup.log);
        first = try std.math.add(u64, first, t.calls);
    }
    if (first != @as(u64, calls) + 1) return error.InvalidSharedTruthSpan;
}
pub fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truth: *const R.TruthSetup, requests: []const Request, expected: Expected) !u32 {
    const calls = try admitCpu(a, setups, requests, expected);
    try validateSpans(&.{.{ .setup = truth, .first_id = 1, .calls = calls }}, calls);
    return calls;
}
pub fn admitBounded(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const Truth, requests: []const Request, expected: Expected) !u32 {
    if (truths.len > 65535 or setups.len > 65535 - truths.len) return error.InvalidSharedTruthInventory;
    const calls = try admitCpu(a, setups, requests, expected);
    try validateSpans(truths, calls);
    return calls;
}
pub fn beginCpu(ch: *P.T.P.Channel, s: *const R.CpuSetup, r: Request, expected: Expected, index: usize, first_step: u64, first_id: u32) !void {
    try P.beginMaterials(ch, &s.materials, r.base, expected, index, first_step);
    ch.mixU32s(&.{ 0x574b5452, 2, 0, @import("../../protocol.zig").Old.CLAIM_COUNT + 5, r.calls, first_id, s.bridge_log, B.layout.FIXED, B.layout.MAIN, B.layout.INTERACTION, 3, 19, 14, 11 });
}
pub fn beginTruth(ch: *P.T.P.Channel, s: *const R.TruthSetup, calls: u32, expected: Expected) void {
    P.T.P.config().mixInto(ch);
    ch.mixU32s(&.{ 0x574b5452, 2, 1, 3, calls, s.log, K.layout.FIXED, K.layout.MAIN, K.layout.INTERACTION, 4, 11 });
    P.Old.digest(ch, expected.program_identity);
    P.Old.digest(ch, expected.admission.image_identity);
    ch.mixU64(expected.total_steps);
    ch.mixU64(expected.max_total_steps);
    ch.mixU64(expected.admission.initial_pc);
    for (expected.admission.initial_registers) |x| ch.mixU64(x);
    ch.mixU64(expected.final_pc);
    for (expected.final_registers) |x| ch.mixU64(x);
    for ([_]u32{ s.log, 13, 10 }, [_][3]u32{ .{ K.layout.FIXED, K.layout.MAIN, K.layout.INTERACTION }, .{ 7, 1, 4 }, .{ 7, 1, 4 } }, 0..) |log, widths, ordinal| ch.mixU32s(&.{ @intCast(ordinal), log, widths[0], widths[1], widths[2] });
}
pub fn shared(manifest: *const Manifest) !Shared {
    try manifest.check(manifest.specs);
    var ch = P.T.P.Channel{};
    ch.mixU32s(&.{ 0x574b544d, 2 });
    P.Old.digest(&ch, manifest.digest);
    ch.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallenges = undefined;
    ram.offset = ch.drawSecureFelt();
    for (&ram.coefficients) |*v| v.* = ch.drawSecureFelt();
    ch.mixU32s(&.{ 0x4b494f31, 11 });
    return .{ .ram = ram, .io = K.equations.Io.draw(&ch) };
}
pub fn drawCpu(ch: *P.T.P.Channel, manifest: *const Manifest, index: usize) !P.Old.Draw {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x574b5453, 2, 0, @intCast(index) });
    P.Old.digest(ch, manifest.digest);
    var out = P.Old.draw(ch);
    out.memory.ram = common.ram;
    return out;
}
pub fn drawTruth(ch: *P.T.P.Channel, manifest: *const Manifest) !K.equations.Challenges {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x574b5453, 2, 1 });
    P.Old.digest(ch, manifest.digest);
    ch.mixU32s(&.{ 0x4b434849, 6 });
    const chi = K.equations.Lookup.draw(ch);
    ch.mixU32s(&.{ 0x4b584f52, 6 });
    return .{ .chi = chi, .xor5 = K.equations.Lookup.draw(ch), .io = common.io };
}

pub fn beginCpuFor(mode: Mode, ch: *P.T.P.Channel, s: *const R.CpuSetup, r: Request, expected: Expected, index: usize, first_step: u64, first_id: u32, truths: usize) !void {
    try beginCpu(ch, s, r, expected, index, first_step, first_id);
    if (mode == .bounded_v3) ch.mixU32s(&.{ 0x574b4252, 3, @intCast(truths) });
}
pub fn beginTruthFor(mode: Mode, ch: *P.T.P.Channel, t: Truth, expected: Expected, ordinal: usize, truths: usize) void {
    beginTruth(ch, t.setup, t.calls, expected);
    if (mode == .bounded_v3) ch.mixU32s(&.{ 0x574b4252, 3, @intCast(ordinal), @intCast(truths), t.first_id });
}
fn sharedFor(mode: Mode, manifest: *const Manifest) !Shared {
    if (mode == .single_v2) return shared(manifest);
    try manifest.check(manifest.specs);
    var ch = P.T.P.Channel{};
    ch.mixU32s(&.{ 0x574b544d, 3 });
    P.Old.digest(&ch, manifest.digest);
    ch.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallenges = undefined;
    ram.offset = ch.drawSecureFelt();
    for (&ram.coefficients) |*v| v.* = ch.drawSecureFelt();
    ch.mixU32s(&.{ 0x4b494f31, 11 });
    return .{ .ram = ram, .io = K.equations.Io.draw(&ch) };
}
pub fn drawCpuFor(mode: Mode, ch: *P.T.P.Channel, manifest: *const Manifest, index: usize) !P.Old.Draw {
    if (mode == .single_v2) return drawCpu(ch, manifest, index);
    const common = try sharedFor(mode, manifest);
    ch.mixU32s(&.{ 0x574b5453, 3, 0, @intCast(index) });
    P.Old.digest(ch, manifest.digest);
    var out = P.Old.draw(ch);
    out.memory.ram = common.ram;
    return out;
}
pub fn drawTruthFor(mode: Mode, ch: *P.T.P.Channel, manifest: *const Manifest, ordinal: usize) !K.equations.Challenges {
    if (mode == .single_v2) return drawTruth(ch, manifest);
    const common = try sharedFor(mode, manifest);
    ch.mixU32s(&.{ 0x574b5453, 3, 1, @intCast(ordinal) });
    P.Old.digest(ch, manifest.digest);
    ch.mixU32s(&.{ 0x4b434849, 6 });
    const chi = K.equations.Lookup.draw(ch);
    ch.mixU32s(&.{ 0x4b584f52, 6 });
    return .{ .chi = chi, .xor5 = K.equations.Lookup.draw(ch), .io = common.io };
}
pub fn sharedBounded(manifest: *const Manifest) !Shared {
    return sharedFor(.bounded_v3, manifest);
}
