//! One sealed execution inventory for CPU + optional service bridges + bounded
//! truth workers. Only this receiver-selected protocol draws shared challenges.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const H = A.crypto.sha256;
const Ar = A.crypto.arith256;
const G = @import("../protocol.zig");
const R = @import("roster.zig");
const T = @import("types.zig");
pub const Expected = G.Expected;
pub const Manifest = G.Manifest;
pub const CORE_CLAIM_COUNT = G.Old.CLAIM_COUNT;
/// v2 CPU claim vector (three optional bridges, five claims each).
pub const CPU_CLAIM_COUNT = CORE_CLAIM_COUNT + 15;
/// A shard with the v3 SHA-256 bridge appends its five claims.
pub const CPU_CLAIM_COUNT_V3 = CORE_CLAIM_COUNT + 20;
pub const Request = struct { base: G.Old.Request, calls: [T.FAMILIES]u32, bulk: T.BulkCounts = .{} };
const BM = A.crypto.bulk_memory;
/// Admitted bulk-memory geometry and masses of one CPU proof. RAM14 gains
/// 6 fractions per call (three packet reads), 4 per copied and 2 per filled
/// word; OWNER19 gains 3 per call (ECALL consume + token emit, one weight zero)
/// and 1 per body start; U16 gains range16Count(kind) per physical row.
pub fn admitBulk(setup: *const R.CpuSetup, r: Request) !struct { ram: u64, range16: u64 } {
    const logs = setup.bridges.bulk;
    var range16: u64 = 0;
    for (T.bulk_kinds) |kind| {
        const rows = r.bulk.rows(kind);
        const log = logs.at(kind);
        if ((log != null) != (rows != 0)) return error.InvalidCombinedBridgePresence;
        if (log) |l| {
            _ = try BM.types.validateGeometry(kind, rows, l);
            range16 = try std.math.add(u64, range16, @as(u64, BM.layout.range16Count(kind)) << @intCast(l));
        }
    }
    // Every body word belongs to one call of at most MAX_WORDS words.
    if ((r.bulk.copy_words != 0 or r.bulk.set_words != 0) and r.bulk.calls == 0) return error.InvalidCombinedBridgePresence;
    if (@as(u64, r.bulk.copy_words) + r.bulk.set_words > @as(u64, r.bulk.calls) * BM.types.MAX_WORDS) return error.InvalidCombinedServiceCount;
    const ram = 6 * @as(u64, r.bulk.calls) + 4 * @as(u64, r.bulk.copy_words) + 2 * @as(u64, r.bulk.set_words);
    return .{ .ram = ram, .range16 = range16 };
}

pub fn firstIds(requests: []const Request, index: usize) ![T.FAMILIES]u32 {
    if (index > requests.len) return error.InvalidCombinedOrdinal;
    var first: [T.FAMILIES]u64 = @splat(1);
    for (requests[0..index]) |r| for (0..T.FAMILIES) |k| {
        first[k] = try std.math.add(u64, first[k], r.calls[k]);
    };
    var out: [T.FAMILIES]u32 = undefined;
    for (first, &out) |f, *o| {
        if (f >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
        o.* = @intCast(f);
    }
    return out;
}
pub fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const Request, expected: Expected) ![T.FAMILIES]u32 {
    if (setups.len == 0 or setups.len > 65535 or truths.len > 65535 - setups.len or setups.len != requests.len) return error.InvalidCombinedInventory;
    const suite = setups[0].materials.suite;
    try suite.validate();
    for (setups) |s| {
        if (!s.materials.suite.eql(suite) or !s.key.suite.eql(suite)) return error.MixedWord16PcsSuites;
    }
    for (truths) |t| if (!t.key().suite.eql(suite)) return error.MixedWord16PcsSuites;
    const mats = try a.alloc(*const @import("../../word16_execution/setup.zig").Materials, setups.len);
    defer a.free(mats);
    const rr = try a.alloc(G.Old.Request, setups.len);
    defer a.free(rr);
    var totals: [T.FAMILIES]u64 = @splat(0);
    var ram: u64 = 0;
    for (setups, requests, mats, rr) |setup, req, *m, *old| {
        m.* = &setup.materials;
        old.* = req.base;
        if (@as(u64, req.calls[0]) + req.calls[1] + req.calls[2] + req.calls[3] + req.calls[4] + req.bulk.calls + req.base.memory.ls_count > req.base.cpu.steps) return error.InvalidCombinedServiceCount;
        const bulk = try admitBulk(setup, req);
        var mass16 = try std.math.add(u64, try setup.materials.geometry.range16Mass(), bulk.range16);
        var mass8 = try setup.materials.geometry.range8Mass();
        for (0..T.FAMILIES) |k| {
            const family: T.Family = @enumFromInt(k);
            const log = setup.bridges.at(family);
            if (totals[k] >= core.fields.m31.Modulus - 1) return error.CombinedLookupMassExceeded;
            if ((log != null) != (req.calls[k] != 0)) return error.InvalidCombinedBridgePresence;
            if (log) |l| {
                if (k == 0) {
                    _ = try K.word16_bridge.types.validateGeometry(req.calls[k], @intCast(1 + totals[k]), l);
                } else {
                    _ = try S.word16_bridge.types.validateGeometry(T.bridgeKind(family), req.calls[k], @intCast(1 + totals[k]), l);
                }
                const n = @as(u64, 1) << @intCast(l);
                mass16 = try std.math.add(u64, mass16, (if (k == 0) @as(u64, K.word16_bridge.layout.U16.len) else S.word16_bridge.layout.U16.len) * n);
                mass8 = try std.math.add(u64, mass8, (if (k == 0) @as(u64, K.word16_bridge.layout.U8.len) else S.word16_bridge.layout.U8.len) * n);
            }
            totals[k] = try std.math.add(u64, totals[k], req.calls[k]);
        }
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        ram = try std.math.add(u64, ram, 2 * @as(u64, req.base.memory.ls_count));
        for (0..T.FAMILIES) |k| ram = try std.math.add(u64, ram, 2 * T.words(@enumFromInt(k)) * req.calls[k]);
        ram = try std.math.add(u64, ram, bulk.ram);
    }
    try G.validateMaterials(mats, rr, expected);
    ram = try std.math.add(u64, ram, rr[0].memory.initial.len + rr[rr.len - 1].memory.terminal.len);
    if (ram >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
    if (50 * totals[0] >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
    var next: [T.FAMILIES]u64 = @splat(1);
    var previous: u8 = 0;
    var wire: u64 = 0;
    for (1..T.FAMILIES) |k| wire = try std.math.add(u64, wire, T.bridgeWires(@enumFromInt(k)) * totals[k]);
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
            .sha256 => |t| {
                try H.layout.validateGeometry(t.calls, t.first_id, t.setup.log);
                wire = try std.math.add(u64, wire, 4 * @as(u64, t.calls));
            },
            .arith256_mod => |t| {
                try Ar.layout.validateGeometry(t.calls, t.first_id, t.setup.log);
                wire = try std.math.add(u64, wire, Ar.layout.WIRE_FRACTIONS * @as(u64, t.calls));
            },
        }
        next[family] = try std.math.add(u64, next[family], truth.count());
    }
    if (wire >= core.fields.m31.Modulus) return error.CombinedLookupMassExceeded;
    var out: [T.FAMILIES]u32 = undefined;
    for (next, totals, &out) |n, total, *o| {
        if (n != total + 1 or total > std.math.maxInt(u32)) return error.InvalidCombinedTruthSpan;
        o.* = @intCast(total);
    }
    return out;
}
pub fn beginCpu(ch: *G.T.P.Channel, s: *const R.CpuSetup, r: Request, expected: Expected, index: usize, first_step: u64, first: [T.FAMILIES]u32) !void {
    try G.beginMaterials(ch, &s.materials, r.base, expected, index, first_step);
    ch.mixU32s(&.{ 0x57534345, 1, 0, CPU_CLAIM_COUNT, 19, 14, 11, 35, 0x10001, 0x20011, 0x20012 });
    for (0..T.V2_FAMILIES) |k| {
        const f: T.Family = @enumFromInt(k);
        ch.mixU32s(&.{ @intCast(k), r.calls[k], first[k], @intFromBool(s.bridges.at(f) != null), s.bridges.at(f) orelse 0 });
        if (s.bridges.at(f) != null) for (T.widths(f)) |width| ch.mixU32s(&.{@intCast(width)});
    }
    // v3 SHA-256 bridge: appended only when present, so every v2 shard's
    // spec is unchanged. Presence still binds tag, claim count and geometry.
    if (s.bridges.sha256) |log| {
        ch.mixU32s(&.{ 0x57534833, 1, CPU_CLAIM_COUNT_V3, 0x30010, @intFromEnum(T.Family.sha256), r.calls[3], first[3], H.layout.PROGRAM_KIND, log });
        for (T.widths(.sha256)) |width| ch.mixU32s(&.{@intCast(width)});
    } else if (r.calls[3] != 0) return error.InvalidCombinedBridgePresence;
    // v3 arith256_mod bridge: same rule, its own domain word and claim count.
    if (s.bridges.arith256_mod) |log| {
        ch.mixU32s(&.{ 0x57534134, 1, 5, 0x30021, @intFromEnum(T.Family.arith256_mod), r.calls[4], first[4], Ar.layout.PROGRAM_KIND, log });
        for (T.widths(.arith256_mod)) |width| ch.mixU32s(&.{@intCast(width)});
    } else if (r.calls[4] != 0) return error.InvalidCombinedBridgePresence;
    // Bulk-memory extension: mixed only when present, so v2 transcripts are unchanged.
    if (s.bridges.bulk.any() or r.bulk.any()) {
        ch.mixU32s(&.{ 0x424d454d, 1, 0x30001, 0x30002, BM.types.TOKEN_COPY, BM.types.TOKEN_SET, @intCast(BM.types.MAX_BYTES) });
        for (T.bulk_kinds, 0..) |kind, k| {
            ch.mixU32s(&.{ @intCast(k), r.bulk.rows(kind), @intFromBool(s.bridges.bulk.at(kind) != null), s.bridges.bulk.at(kind) orelse 0, @intCast(BM.layout.constraints(kind)) });
            if (s.bridges.bulk.at(kind) != null) for (T.bulkWidths(kind)) |width| ch.mixU32s(&.{@intCast(width)});
        }
    }
}
pub fn beginTruth(ch: *G.T.P.Channel, truth: R.Truth, expected: Expected, ordinal: usize) void {
    truth.key().suite.config().mixInto(ch);
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
        .secp => |t| {
            const policy = @import("../secp/roster.zig").TruthSetup.byte_policy;
            S.byte_encoding.mix(ch, policy);
            ch.mixU32s(&.{ t.setup.logs[0], t.setup.logs[1], 8, S.layout.FIXED, @intCast(S.layout.main(.product)), @intCast(S.layout.interactionFor(.product, policy)), @intCast(S.layout.main(.linear)), @intCast(S.layout.interactionFor(.linear, policy)), 35 });
        },
        .sha256 => |t| ch.mixU32s(&.{ 0x53484132, t.setup.log, H.layout.FIXED, H.layout.MAIN, H.layout.INTERACTION, H.layout.CONSTRAINTS, 35, H.layout.PROGRAM_KIND }),
        .arith256_mod => |t| ch.mixU32s(&.{ 0x41524d34, t.setup.log, Ar.layout.FIXED, Ar.layout.MAIN, Ar.layout.INTERACTION, Ar.layout.CONSTRAINTS, 35, Ar.layout.PROGRAM_KIND, Ar.layout.BYTE_QUERIES }),
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
    return G.Old.drawWithSharedRam(ch, common.ram);
}
pub const TruthDraw = union(enum) { keccak: K.equations.Challenges, secp: S.equations.Challenges, sha256: S.equations.Wire, arith256_mod: Ar.equations.Challenges };
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
        // No local relation: every SHA-256 lookup is the shared Wire35 bus.
        .sha256 => .{ .sha256 = common.wire },
        // Local BYTE point, drawn after this truth's MAIN root is sealed.
        .arith256_mod => block: {
            ch.mixU32s(&.{ 0x41524231, 8 });
            break :block .{ .arith256_mod = .{ .bytes = ch.drawSecureFelt(), .wire = common.wire } };
        },
    };
}
