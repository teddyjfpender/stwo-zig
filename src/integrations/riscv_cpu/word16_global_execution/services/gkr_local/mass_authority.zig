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
