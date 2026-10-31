//! One sealed execution inventory for CPU + optional service bridges + bounded
//! truth workers. Only this receiver-selected protocol draws shared challenges.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const G = @import("../protocol.zig");
const R = @import("roster.zig");
const T = @import("types.zig");
pub const Expected = G.Expected;
pub const Manifest = G.Manifest;
pub const CORE_CLAIM_COUNT = G.Old.CLAIM_COUNT;
pub const CPU_CLAIM_COUNT = CORE_CLAIM_COUNT + 15;
pub const Request = struct { base: G.Old.Request, calls: [3]u32 };
pub fn firstIds(requests: []const Request, index: usize) ![3]u32 {
    if (index > requests.len) return error.InvalidCombinedOrdinal;
    var first: [3]u64 = @splat(1);
    for (requests[0..index]) |r| for (0..3) |k| {
        first[k] = try std.math.add(u64, first[k], r.calls[k]);
    };
    var out: [3]u32 = undefined;
    for (first, &out) |f, *o| {
        if (f >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
        o.* = @intCast(f);
    }
    return out;
}
pub fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const Request, expected: Expected) ![3]u32 {
    if (setups.len == 0 or setups.len > 65535 or truths.len > 65535 - setups.len or setups.len != requests.len) return error.InvalidCombinedInventory;
    const mats = try a.alloc(*const @import("../../word16_execution/setup.zig").Materials, setups.len);
    defer a.free(mats);
    const rr = try a.alloc(G.Old.Request, setups.len);
    defer a.free(rr);
    var totals: [3]u64 = @splat(0);
    var ram: u64 = 0;
    for (setups, requests, mats, rr) |setup, req, *m, *old| {
        m.* = &setup.materials;
        old.* = req.base;
        if (@as(u64, req.calls[0]) + req.calls[1] + req.calls[2] + req.base.memory.ls_count > req.base.cpu.steps) return error.InvalidCombinedServiceCount;
        var mass16 = try setup.materials.geometry.range16Mass();
        var mass8 = try setup.materials.geometry.range8Mass();
        for (0..3) |k| {
            const family: T.Family = @enumFromInt(k);
            const log = setup.bridges.at(family);
            if (totals[k] >= core.fields.m31.Modulus - 1) return error.CombinedLookupMassExceeded;
            if ((log != null) != (req.calls[k] != 0)) return error.InvalidCombinedBridgePresence;
            if (log) |l| {
                if (k == 0) {
                    _ = try K.word16_bridge.types.validateGeometry(req.calls[k], @intCast(1 + totals[k]), l);
                } else {
                    _ = try S.word16_bridge.types.validateGeometry(@enumFromInt(k), req.calls[k], @intCast(1 + totals[k]), l);
                }
                const n = @as(u64, 1) << @intCast(l);
                mass16 = try std.math.add(u64, mass16, (if (k == 0) @as(u64, K.word16_bridge.layout.U16.len) else S.word16_bridge.layout.U16.len) * n);
                mass8 = try std.math.add(u64, mass8, (if (k == 0) @as(u64, K.word16_bridge.layout.U8.len) else S.word16_bridge.layout.U8.len) * n);
            }
            totals[k] = try std.math.add(u64, totals[k], req.calls[k]);
        }
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        ram = try std.math.add(u64, ram, 2 * @as(u64, req.base.memory.ls_count) + 50 * @as(u64, req.calls[0]) + 48 * @as(u64, req.calls[1]) + 24 * @as(u64, req.calls[2]));
    }
    try G.validateMaterials(mats, rr, expected);
    ram = try std.math.add(u64, ram, rr[0].memory.initial.len + rr[rr.len - 1].memory.terminal.len);
    if (ram >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
    if (50 * totals[0] >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
    var next: [3]u64 = @splat(1);
    var previous: u8 = 0;
    var wire: u64 = 9 * totals[1] + 6 * totals[2];
    for (truths) |truth| {
        const family = @intFromEnum(truth.family());
        if (family < previous or truth.count() == 0 or truth.first() != next[family]) return error.InvalidCombinedTruthSpan;
        previous = family;
        switch (truth) {
            .keccak => |t| try K.layout.validateGeometry(t.calls, t.first_id, t.setup.log),
            .secp => |t| {
                const p = S.program.get(t.setup.kind);
                const mass = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = p, .calls = t.calls, .first_id = t.first_id, .log = t.setup.logs[0] }, .{ .kind = .linear, .program = p, .calls = t.calls, .first_id = t.first_id, .log = t.setup.logs[1] } }, &.{});
                wire = try std.math.add(u64, wire, mass.wires);
            },
        }
        next[family] = try std.math.add(u64, next[family], truth.count());
    }
    if (wire >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
    var out: [3]u32 = undefined;
    for (next, totals, &out) |n, total, *o| {
        if (n != total + 1 or total > std.math.maxInt(u32)) return error.InvalidCombinedTruthSpan;
        o.* = @intCast(total);
    }
    return out;
}
pub fn beginCpu(ch: *G.T.P.Channel, s: *const R.CpuSetup, r: Request, expected: Expected, index: usize, first_step: u64, first: [3]u32) !void {
    try G.beginMaterials(ch, &s.materials, r.base, expected, index, first_step);
    ch.mixU32s(&.{ 0x57534345, 1, 0, CPU_CLAIM_COUNT, 19, 14, 11, 35, 0x10001, 0x20011, 0x20012 });
    for (0..3) |k| {
        const f: T.Family = @enumFromInt(k);
        ch.mixU32s(&.{ @intCast(k), r.calls[k], first[k], @intFromBool(s.bridges.at(f) != null), s.bridges.at(f) orelse 0 });
        if (s.bridges.at(f) != null) for (T.widths(f)) |width| ch.mixU32s(&.{@intCast(width)});
    }
}
pub fn beginTruth(ch: *G.T.P.Channel, truth: R.Truth, expected: Expected, ordinal: usize) void {
    G.T.P.config().mixInto(ch);
    ch.mixU32s(&.{ 0x57534345, 1, 1, @intCast(ordinal), @intFromEnum(truth.family()), truth.first(), truth.count(), 3 });
    G.Old.digest(ch, expected.program_identity);
    G.Old.digest(ch, expected.admission.image_identity);
    ch.mixU64(expected.total_steps);
    ch.mixU64(expected.max_total_steps);
    ch.mixU64(expected.admission.initial_pc);
    for (expected.admission.initial_registers) |x| ch.mixU64(x);
    ch.mixU64(expected.final_pc);
    for (expected.final_registers) |x| ch.mixU64(x);
    switch (truth) {
        .keccak => |t| ch.mixU32s(&.{ t.setup.log, 13, 10, K.layout.FIXED, K.layout.MAIN, K.layout.INTERACTION, 11 }),
        .secp => |t| ch.mixU32s(&.{ t.setup.logs[0], t.setup.logs[1], 8, S.layout.FIXED, @intCast(S.layout.main(.product)), @intCast(S.layout.interaction(.product)), @intCast(S.layout.main(.linear)), @intCast(S.layout.interaction(.linear)), 35 }),
    }
}
pub const Shared = struct { ram: A.memory.closed_ram.types.RamChallenges, kio: K.equations.Io, wire: S.equations.Wire };
pub fn shared(manifest: *const Manifest) !Shared {
    try manifest.check(manifest.specs);
    var ch = G.T.P.Channel{};
    ch.mixU32s(&.{ 0x5753434d, 1 });
    G.Old.digest(&ch, manifest.digest);
    ch.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallenges = undefined;
    ram.offset = ch.drawSecureFelt();
    for (&ram.coefficients) |*c| c.* = ch.drawSecureFelt();
    ch.mixU32s(&.{ 0x4b494f31, 11 });
    const io = K.equations.Io.draw(&ch);
    ch.mixU32s(&.{ 0x53574952, 35 });
    return .{ .ram = ram, .kio = io, .wire = S.equations.Wire.draw(&ch) };
}
pub fn drawCpu(ch: *G.T.P.Channel, manifest: *const Manifest, index: usize) !G.Old.Draw {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x57534332, 1, 0, @intCast(index) });
    G.Old.digest(ch, manifest.digest);
    var out = G.Old.draw(ch);
    out.memory.ram = common.ram;
    return out;
}
pub const TruthDraw = union(enum) { keccak: K.equations.Challenges, secp: S.equations.Challenges };
pub fn drawTruth(ch: *G.T.P.Channel, manifest: *const Manifest, truth: R.Truth, ordinal: usize) !TruthDraw {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x57534332, 1, 1, @intCast(ordinal), @intFromEnum(truth.family()) });
    G.Old.digest(ch, manifest.digest);
    return switch (truth) {
        .keccak => block: {
            ch.mixU32s(&.{ 0x4b434849, 6 });
            const chi = K.equations.Lookup.draw(ch);
            ch.mixU32s(&.{ 0x4b584f52, 6 });
            break :block .{ .keccak = .{ .chi = chi, .xor5 = K.equations.Lookup.draw(ch), .io = common.kio } };
        },
        .secp => .{ .secp = .{ .polynomial = ch.drawSecureFelt(), .bytes = ch.drawSecureFelt(), .wire = common.wire } },
    };
}
