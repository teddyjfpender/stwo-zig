//! One fraction authority for streaming native inputs and OODS projections.
//! Namespace challenges are independent and drawn only after all MAIN roots.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak_sponge;
const R = @import("authority.zig");
const Source = @import("source.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
pub fn TupleFor(comptime C: type, comptime n: usize) type {
    return struct { offset: C, coefficients: [n]C };
}
pub fn ChallengesFor(comptime C: type) type {
    return struct { owner: TupleFor(C, 19), and_: TupleFor(C, 3), u16: C, u8: C };
}
pub const Challenges = ChallengesFor(O);
pub fn drawFor(comptime C: type, channel: anytype) ChallengesFor(C) {
    channel.mixU32s(&.{0x53504f57});
    var owner: TupleFor(C, 19) = undefined;
    owner.offset = channel.drawSecureFelt();
    for (&owner.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{0x5350414e});
    var and_: TupleFor(C, 3) = undefined;
    and_.offset = channel.drawSecureFelt();
    for (&and_.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{0x53505531});
    const range16 = channel.drawSecureFelt();
    channel.mixU32s(&.{0x53505538});
    const range8 = channel.drawSecureFelt();
    return .{ .owner = owner, .and_ = and_, .u16 = range16, .u8 = range8 };
}
pub fn List(comptime F: type, comptime role: R.Role) type {
    return struct {
        n: [R.localQueries(role)]F = undefined,
        d: [R.localQueries(role)]E.SecureFor(F) = undefined,
        count: usize = 0,
        ch: ChallengesFor(E.ConstFor(F)),
        pub fn emit(self: *@This(), relation: usize, tuple: anytype, weight: F) void {
            if (relation == K.equations.RAM or relation == K.equations.IO) return;
            const denominator = switch (tuple.len) {
                19 => E.denominatorFor(F, self.ch.owner.offset, &self.ch.owner.coefficients, &tuple, true),
                3 => E.denominatorFor(F, self.ch.and_.offset, &self.ch.and_.coefficients, &tuple, true),
                1 => E.splatFor(F, if (relation == K.equations.RANGE16) self.ch.u16 else self.ch.u8).sub(E.liftFor(F, tuple[0])),
                else => unreachable,
            };
            self.n[self.count] = weight;
            self.d[self.count] = denominator;
            self.count += 1;
        }
    };
}
pub fn collect(comptime F: type, comptime role: R.Role, f: *const [R.fixedWidth(role)]F, m: *const [R.mainWidth(role)]F, first_id: E.CountFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F))) List(F, role) {
    var list = List(F, role){ .ch = ch };
    Source.emitRaw(role, F, f, m, first_id, &list);
    return list;
}
pub const Provider = struct {
    source: *const Source.Source,
    pub fn validate(self: @This(), g: R.Geometry) !void {
        try self.source.validate(g);
    }
    pub fn emitRange(self: @This(), instance: R.Instance, logical: usize, first: usize, n: []M, d: []O, ch: Challenges) !void {
        if (first > instance.queries() or n.len > instance.queries() - first or n.len != d.len) return error.SpongeLocalQuery;
        inline for (R.roles) |role| if (instance.role == role) {
            const row = self.source.row(role, logical);
            const fixed = Source.fixedRow(role, logical, instance.row_log);
            var lifted: [R.mainWidth(role)]O = undefined;
            var ff: [R.fixedWidth(role)]O = undefined;
            for (row, &lifted) |v, *out| out.* = O.fromBase(v);
            for (fixed, &ff) |v, *out| out.* = O.fromBase(v);
            const list = collect(O, role, &ff, &lifted, self.source.geometry.first_id, ch);
            if (list.count != instance.queries()) return error.SpongeLocalQuery;
            for (n, d, 0..) |*nn, *dd, i| {
                const coords = list.n[first + i].toM31Array();
                for (coords[1..]) |v| if (!v.isZero()) return error.SpongeLocalNonbaseWeight;
                nn.* = coords[0];
                dd.* = list.d[first + i];
            }
            return;
        };
        unreachable;
    }
};
