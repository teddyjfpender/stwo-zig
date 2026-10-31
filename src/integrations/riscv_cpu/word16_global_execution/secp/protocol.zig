//! Explicit LE-word secp execution join. No caller-supplied challenge vector.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const B = S.word16_bridge;
const G = @import("../protocol.zig");
const R = @import("roster.zig");
pub const Expected = G.Expected;
pub const Manifest = G.Manifest;
pub const CORE_CLAIM_COUNT = if (@hasDecl(G.Old, "CLAIM_COUNT")) G.Old.CLAIM_COUNT else @typeInfo(@typeInfo(@TypeOf(G.Old.Claims.values)).@"fn".return_type.?).array.len;
pub const CPU_CLAIM_COUNT = CORE_CLAIM_COUNT + 10;
pub const Request = struct { base: G.Old.Request, calls: [2]u32 };
pub fn firstCall(requests: []const Request, index: usize, family: usize) !u32 {
    if (index > requests.len or family >= 2) return error.InvalidSecpOrdinal;
    var first: u64 = 1;
    for (requests[0..index]) |r| first = try std.math.add(u64, first, r.calls[family]);
    if (first >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
    return @intCast(first);
}
pub fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: [2]*const R.TruthSetup, requests: []const Request, expected: Expected) ![2]u32 {
    if (setups.len == 0 or setups.len > 65533 or setups.len != requests.len) return error.InvalidSecpInventory;
    const mats = try a.alloc(*const @import("../../word16_execution/setup.zig").Materials, setups.len);
    defer a.free(mats);
    const rr = try a.alloc(G.Old.Request, setups.len);
    defer a.free(rr);
    var totals: [2]u64 = @splat(0);
    var ram: u64 = 0;
    for (setups, requests, mats, rr) |setup, req, *m, *old| {
        m.* = &setup.materials;
        old.* = req.base;
        if (@as(u64, req.calls[0]) + req.calls[1] + req.base.memory.ls_count > req.base.cpu.steps) return error.InvalidSecpServiceCount;
        var mass16 = try setup.materials.geometry.range16Mass();
        var mass8 = try setup.materials.geometry.range8Mass();
        for (0..2) |k| {
            const kind: S.program.Kind = @enumFromInt(k + 1);
            _ = try B.types.validateGeometry(kind, req.calls[k], @intCast(1 + totals[k]), setup.bridge_logs[k]);
            const n = @as(u64, 1) << @intCast(setup.bridge_logs[k]);
            mass16 = try std.math.add(u64, mass16, B.layout.U16.len * n);
            mass8 = try std.math.add(u64, mass8, B.layout.U8.len * n);
            totals[k] = try std.math.add(u64, totals[k], req.calls[k]);
            ram = try std.math.add(u64, ram, 8 * Tcoords(kind) * @as(u64, req.calls[k]));
        }
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.SecpRangeMassExceeded;
        ram = try std.math.add(u64, ram, 2 * @as(u64, req.base.memory.ls_count));
    }
    try G.validateMaterials(mats, rr, expected);
    var wire: u64 = 0;
    for (truths, 0..) |truth, k| {
        if (@intFromEnum(truth.kind) != k + 1 or totals[k] > std.math.maxInt(u32)) return error.InvalidSecpTruthKind;
        const p = S.program.get(truth.kind);
        const mass = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = p, .calls = @intCast(totals[k]), .first_id = 1, .log = truth.logs[0] }, .{ .kind = .linear, .program = p, .calls = @intCast(totals[k]), .first_id = 1, .log = truth.logs[1] } }, &.{});
        wire = try std.math.add(u64, wire, mass.wires);
        wire = try std.math.add(u64, wire, (Tcoords(truth.kind) + 3) * totals[k]);
    }
    ram = try std.math.add(u64, ram, rr[0].memory.initial.len + rr[rr.len - 1].memory.terminal.len);
    if (ram >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
    if (wire >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
    return .{ @intCast(totals[0]), @intCast(totals[1]) };
}
fn Tcoords(kind: S.program.Kind) u64 {
    return @intCast(B.types.coordinates(kind));
}
pub fn beginCpu(ch: *G.T.P.Channel, s: *const R.CpuSetup, r: Request, expected: Expected, index: usize, first_step: u64, ids: [2]u32) !void {
    try G.beginMaterials(ch, &s.materials, r.base, expected, index, first_step);
    ch.mixU32s(&.{ 0x57534543, 1, 0, CPU_CLAIM_COUNT, r.calls[0], r.calls[1], ids[0], ids[1], s.bridge_logs[0], s.bridge_logs[1], B.layout.FIXED, B.layout.MAIN, B.layout.INTERACTION, 3, 19, 14, 35, 0x20011, 0x20012 });
}
pub fn beginTruth(ch: *G.T.P.Channel, s: *const R.TruthSetup, calls: u32, expected: Expected) void {
    G.T.P.config().mixInto(ch);
    ch.mixU32s(&.{ 0x57534543, 1, 1, 3, @intFromEnum(s.kind), calls, 1, s.logs[0], s.logs[1], 35, 0x52434231 });
    G.Old.digest(ch, expected.program_identity);
    G.Old.digest(ch, expected.admission.image_identity);
    ch.mixU64(expected.total_steps);
    ch.mixU64(expected.max_total_steps);
    ch.mixU64(expected.admission.initial_pc);
    for (expected.admission.initial_registers) |x| ch.mixU64(x);
    ch.mixU64(expected.final_pc);
    for (expected.final_registers) |x| ch.mixU64(x);
    for (0..3) |tree| {
        for (R.TruthSetup.widths(tree)) |width| ch.mixU32s(&.{@intCast(width)});
    }
}
pub const Shared = struct { ram: A.memory.closed_ram.types.RamChallenges, wire: S.equations.Wire };
pub fn shared(manifest: *const Manifest) !Shared {
    try manifest.check(manifest.specs);
    var ch = G.T.P.Channel{};
    ch.mixU32s(&.{ 0x5753454d, 1 });
    G.Old.digest(&ch, manifest.digest);
    ch.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallenges = undefined;
    ram.offset = ch.drawSecureFelt();
    for (&ram.coefficients) |*c| c.* = ch.drawSecureFelt();
    ch.mixU32s(&.{ 0x53574952, 35 });
    return .{ .ram = ram, .wire = S.equations.Wire.draw(&ch) };
}
pub fn drawCpu(ch: *G.T.P.Channel, manifest: *const Manifest, index: usize) !G.Old.Draw {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x57534532, 1, 0, @intCast(index) });
    G.Old.digest(ch, manifest.digest);
    var out = G.Old.draw(ch);
    out.memory.ram = common.ram;
    return out;
}
pub fn drawTruth(ch: *G.T.P.Channel, manifest: *const Manifest, kind: S.program.Kind) !S.equations.Challenges {
    const common = try shared(manifest);
    ch.mixU32s(&.{ 0x57534532, 1, 1, @intFromEnum(kind) });
    G.Old.digest(ch, manifest.digest);
    return .{ .polynomial = ch.drawSecureFelt(), .bytes = ch.drawSecureFelt(), .wire = common.wire };
}
