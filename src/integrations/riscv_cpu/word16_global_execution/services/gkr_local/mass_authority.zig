//! Ordinary signed global event bounds from request counts and immutable native
//! service topology. These are integers, not claims/residues. Wire uses readonly
//! program-use counts; its coefficients are not all unit weights.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Manifest = @import("manifest.zig");
const Request = @import("../protocol.zig").Request;
const Declaration = @import("../wire.zig").TruthDeclaration;
pub const Signed = struct {
    positive: u64 = 0,
    negative: u64 = 0,
    pub fn absolute(self: Signed) !u64 {
        return std.math.add(u64, self.positive, self.negative);
    }
};
pub const Globals = struct {
    ram: Signed = .{},
    kio: Signed = .{},
    wire: Signed = .{},
    pub fn absolute(self: Globals) !Manifest.Mass {
        return .{ .ram = try self.ram.absolute(), .kio = try self.kio.absolute(), .wire = try self.wire.absolute() };
    }
    pub fn add(self: *Globals, other: Globals) !void {
        inline for (.{ "ram", "kio", "wire" }) |name| {
            @field(self, name).positive = try std.math.add(u64, @field(self, name).positive, @field(other, name).positive);
            @field(self, name).negative = try std.math.add(u64, @field(self, name).negative, @field(other, name).negative);
        }
    }
};
pub const Relation = enum { ram, kio, wire };
/// The same source-owned linear event formula can consume integer values or
/// circuit handles. INITIAL/TERMINAL counts come from actual AIR public rows.
pub fn CpuCountsFor(comptime Scalar: type) type {
    return struct { ls: Scalar, initial: Scalar, terminal: Scalar, calls: [@import("../types.zig").FAMILIES]Scalar,
        dword: Scalar, sponge: [2]Scalar, bulk: [@import("../types.zig").bulk_kinds.len]Scalar };
}
pub fn cpuCounts(request: Request) !CpuCountsFor(u32) {
    var counts: CpuCountsFor(u32) = .{ .ls = request.base.memory.ls_count,
        .initial = std.math.cast(u32, request.base.memory.initial.len) orelse return error.GlobalMassCounterRange,
        .terminal = std.math.cast(u32, request.base.memory.terminal.len) orelse return error.GlobalMassCounterRange,
        .calls = request.calls, .dword = request.ls_dword,
        .sponge = .{ request.sponge.calls, request.sponge.perms }, .bulk = undefined };
    inline for (@import("../types.zig").bulk_kinds, 0..) |kind, i| counts.bulk[i] = request.bulk.rows(kind);
    return counts;
}
/// writer.term(relation, positive, count, coefficient) latches its own errors.
/// No term is a net residual. Both signs of every memory access are retained.
pub fn emitCpuTerms(counts: anytype, writer: anytype) void {
    writer.term(.ram, true, counts.ls, 1); writer.term(.ram, true, counts.terminal, 1);
    writer.term(.ram, false, counts.ls, 1); writer.term(.ram, false, counts.initial, 1);
    const kwords = @typeInfo(@FieldType(A.crypto.keccak.word16_bridge.types.Call, "before")).array.len;
    writer.term(.ram, true, counts.calls[0], kwords); writer.term(.ram, false, counts.calls[0], kwords);
    writer.term(.kio, false, counts.calls[0], 2 * A.crypto.keccak.layout.IO_LANES);
    inline for ([_]A.crypto.secp256k1.program.Kind{ .add, .double }, 1..) |kind, f| {
        const program = A.crypto.secp256k1.program.get(kind);
        writer.term(.ram, true, counts.calls[f], program.inputs * 4); writer.term(.ram, false, counts.calls[f], program.inputs * 4);
        writer.term(.wire, true, counts.calls[f], program.inputs); writer.term(.wire, false, counts.calls[f], program.outputs.len);
    }
    inline for (comptime std.enums.values(@import("../types.zig").Family)) |family| {
        if (@intFromEnum(family) >= 3) {
            const kind = @import("../types.zig").bridgeKind(family);
            const coordinates = A.crypto.secp256k1.word16_bridge.types.coordinates(kind);
            writer.term(.ram, true, counts.calls[@intFromEnum(family)], 4 * coordinates);
            writer.term(.ram, false, counts.calls[@intFromEnum(family)], 4 * coordinates);
            writer.term(.wire, true, counts.calls[@intFromEnum(family)], coordinates);
            writer.term(.wire, false, counts.calls[@intFromEnum(family)], A.crypto.secp256k1.word16_bridge.types.written(kind));
        }
    }
    writer.term(.ram, true, counts.dword, 1); writer.term(.ram, false, counts.dword, 1);
    inline for (.{29,18}, 0..) |coefficient, i| {
        writer.term(.ram, true, counts.sponge[i], coefficient); writer.term(.ram, false, counts.sponge[i], coefficient);
        writer.term(.kio, true, counts.sponge[i], 50); writer.term(.kio, false, counts.sponge[i], 50);
    }
    inline for (@import("../types.zig").bulk_kinds, 0..) |kind, i| {
        const coefficient = A.crypto.bulk_memory.layout.ramCount(kind) / 2;
        writer.term(.ram, true, counts.bulk[i], coefficient); writer.term(.ram, false, counts.bulk[i], coefficient);
    }
}
pub fn evaluateCpuCounts(counts: CpuCountsFor(u32)) !Globals {
    var writer = struct {
        total: Globals = .{}, failure: ?anyerror = null,
        pub fn term(s: *@This(), relation: Relation, positive: bool, count: u32, coefficient: usize) void {
            if (s.failure != null) return;
            const value = std.math.mul(u64, count, coefficient) catch |err| { s.failure = err; return; };
            const signed = switch (relation) { .ram => &s.total.ram, .kio => &s.total.kio, .wire => &s.total.wire };
            const output = if (positive) &signed.positive else &signed.negative;
            output.* = std.math.add(u64, output.*, value) catch |err| { s.failure = err; return; };
        }
    }{};
    emitCpuTerms(counts, &writer);
    if (writer.failure) |err| return err;
    return writer.total;
}
test "shared CPU signed-event visitor agrees with legacy native mass authority" {
    const Cell = A.memory.closed_ram.types.Cell;
    const cells: [5]Cell = @splat(std.mem.zeroes(Cell));
    for (0..4) |case| {
        var request: Request = std.mem.zeroes(Request);
        request.base.memory.initial = cells[0..3];
        request.base.memory.terminal = &cells;
        request.base.memory.ls_count = @intCast(7 * case);
        request.ls_dword = @intCast(11 * case);
        for (&request.calls, 0..) |*calls, family| calls.* = @intCast((family + 1) * case);
        request.sponge = .{ .calls = @intCast(13 * case), .perms = @intCast(17 * case), .first_id = 1 };
        request.bulk = .{ .calls = @intCast(2 * case), .copy_words = @intCast(3 * case), .set_words = @intCast(5 * case),
            .ucopy_rows = @intCast(7 * case), .cmp_calls = @intCast(11 * case), .cmp_words = @intCast(13 * case),
            .jump_calls = @intCast(17 * case), .jump_rows = @intCast(19 * case) };
        try std.testing.expectEqualDeep(try cpu(request), try evaluateCpuCounts(try cpuCounts(request)));
    }
}
pub fn cpu(request: Request) !Globals {
    try @import("service_scope.zig").request(request);
    var out = Globals{};
    out.ram.positive = try std.math.add(u64, request.base.memory.ls_count, request.base.memory.terminal.len);
    out.ram.negative = try std.math.add(u64, request.base.memory.ls_count, request.base.memory.initial.len);
    const kwords = @typeInfo(@FieldType(A.crypto.keccak.word16_bridge.types.Call, "before")).array.len;
    const kw = try std.math.mul(u64, request.calls[0], kwords);
    out.ram.positive = try std.math.add(u64, out.ram.positive, kw);
    out.ram.negative = try std.math.add(u64, out.ram.negative, kw);
    out.kio.negative = try std.math.mul(u64, request.calls[0], 2 * A.crypto.keccak.layout.IO_LANES);
    for ([_]A.crypto.secp256k1.program.Kind{ .add, .double }, request.calls[1..3]) |kind, calls| {
        const program = A.crypto.secp256k1.program.get(kind);
        const words = try std.math.mul(u64, program.inputs, @sizeOf(u256) / @sizeOf(u64));
        const ram = try std.math.mul(u64, calls, words);
        out.ram.positive = try std.math.add(u64, out.ram.positive, ram);
        out.ram.negative = try std.math.add(u64, out.ram.negative, ram);
        out.wire.positive = try std.math.add(u64, out.wire.positive, try std.math.mul(u64, calls, program.inputs));
        out.wire.negative = try std.math.add(u64, out.wire.negative, try std.math.mul(u64, calls, program.outputs.len));
    }
    for (@import("std").enums.values(@import("../types.zig").Family)) |family| {
        if (@intFromEnum(family) < 3) continue;
        const calls = request.calls[@intFromEnum(family)];
        const kind = @import("../types.zig").bridgeKind(family);
        const ram = try std.math.mul(u64, calls, 4 * A.crypto.secp256k1.word16_bridge.types.coordinates(kind));
        out.ram.positive = try std.math.add(u64, out.ram.positive, ram);
        out.ram.negative = try std.math.add(u64, out.ram.negative, ram);
        out.wire.positive = try std.math.add(u64, out.wire.positive, try std.math.mul(u64, calls, A.crypto.secp256k1.word16_bridge.types.coordinates(kind)));
        out.wire.negative = try std.math.add(u64, out.wire.negative, try std.math.mul(u64, calls, A.crypto.secp256k1.word16_bridge.types.written(kind)));
    }
    out.ram.positive = try std.math.add(u64, out.ram.positive, request.ls_dword);
    out.ram.negative = try std.math.add(u64, out.ram.negative, request.ls_dword);
    const sponge_ram = try std.math.add(u64, try std.math.mul(u64, request.sponge.calls, 29), try std.math.mul(u64, request.sponge.perms, 18));
    out.ram.positive = try std.math.add(u64, out.ram.positive, sponge_ram);
    out.ram.negative = try std.math.add(u64, out.ram.negative, sponge_ram);
    const sponge_io = try std.math.mul(u64, try std.math.add(u64, request.sponge.calls, request.sponge.perms), 50);
    out.kio.positive = try std.math.add(u64, out.kio.positive, sponge_io);
    out.kio.negative = try std.math.add(u64, out.kio.negative, sponge_io);
    const bulk = request.bulk.ram();
    if (bulk % 2 != 0) return error.GlobalBulkMassAuthorityMismatch;
    out.ram.positive = try std.math.add(u64, out.ram.positive, bulk / 2);
    out.ram.negative = try std.math.add(u64, out.ram.negative, bulk / 2);
    return out;
}
pub fn truth(d: Declaration) !Globals {
    var out = Globals{};
    if (d.family != .keccak and (@intFromEnum(d.family) >= 3 or d.logs[1] == 0)) {
        _ = try @import("truth_v3_catalog.zig").descriptorForDeclaration(d);
        const kind = @import("../types.zig").bridgeKind(d.family);
        out.wire.positive = try std.math.mul(u64, d.calls, A.crypto.secp256k1.word16_bridge.types.written(kind));
        out.wire.negative = try std.math.mul(u64, d.calls, A.crypto.secp256k1.word16_bridge.types.coordinates(kind));
        return out;
    }
    switch (d.family) {
        .keccak => {
            const policy = try @import("truth_profile.zig").fromDeclaration(d);
            try A.crypto.keccak.layout.validateGeometryFor(policy.geometry(), d.calls, d.first_id, d.logs[0]);
            out.kio.positive = try std.math.mul(u64, d.calls, 2 * A.crypto.keccak.layout.IO_LANES);
        },
        .add, .double => {
            const S = A.crypto.secp256k1;
            const program = S.program.get(if (d.family == .add) .add else .double);
            const admitted = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = program, .calls = d.calls, .first_id = d.first_id, .log = d.logs[0] }, .{ .kind = .linear, .program = program, .calls = d.calls, .first_id = d.first_id, .log = d.logs[1] } }, &.{});
            var positive: u64 = 0;
            var negative: u64 = 0;
            for (program.operations[0..program.length]) |op| {
                positive = try std.math.add(u64, positive, program.uses[op.result]);
                negative = try std.math.add(u64, negative, @intFromBool(op.lhs == .wire));
                negative = try std.math.add(u64, negative, @intFromBool(op.rhs == .wire));
            }
            out.wire = .{ .positive = try std.math.mul(u64, positive, d.calls), .negative = try std.math.mul(u64, negative, d.calls) };
            if (try out.wire.absolute() != admitted.wires) return error.GlobalWireMassAuthorityMismatch;
        },
        else => return error.GkrV3ServiceUnsupported,
    }
    return out;
}
