//! Benchmark-only degree-aware grouping of the ORIGINAL local fraction emitter.
//! No opcode equations, tuple projections or production profile is redefined.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const G = @import("../../../../word16_execution/geometry.zig");
const Role = @import("../../gkr_local/role.zig");
const Table = @import("../../gkr_local/table_role.zig");
const Fn = @import("../../gkr_local/fractions.zig");
const Roster = @import("../../gkr_local/roster.zig");
pub const MAX_TERMS = 128;
pub const MAX_GROUPS = 64;
pub const Term = struct { denominator: u8, weight: u8 };
pub const Group = struct { first: u8, second: ?u8 = null };
pub const Plan = struct {
    terms: usize,
    groups: [MAX_GROUPS]Group = undefined,
    group_count: usize = 0,
    degree: [MAX_TERMS]Term = undefined,
    pub fn width(self: *const @This()) usize {
        return if (self.terms == 0) 0 else 8 * (self.group_count + 1);
    }
    pub fn constraints(self: *const @This()) usize {
        return if (self.terms == 0) 0 else self.group_count + 2;
    }
};
/// Conservative symbolic total degree; cancellation is never assumed. Used
/// only for an immutable grouping catalog, not witness values or claims.
const Degree = struct {
    pub const rv64_external_lane = true;
    pub const rv64_extension_degree = 8;
    d: u8,
    z: bool = false,
    pub fn zero() @This() {
        return .{ .d = 0, .z = true };
    }
    pub fn one() @This() {
        return .{ .d = 0 };
    }
    pub fn fromU32(v: u32) @This() {
        return if (v == 0) zero() else one();
    }
    pub fn fromBase(v: core.fields.m31.M31) @This() {
        return fromU32(v.v);
    }
    pub fn fromQm31(v: core.fields.qm31.QM31) @This() {
        return if (v.isZero()) zero() else one();
    }
    pub fn fromPartialEvals(v: [8]@This()) @This() {
        var r = zero();
        for (v) |x| r = r.add(x);
        return r;
    }
    pub fn add(a: @This(), b: @This()) @This() {
        return .{ .d = @max(a.d, b.d), .z = a.z and b.z };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        return a.add(b);
    }
    pub fn neg(a: @This()) @This() {
        return a;
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        return if (a.z or b.z) zero() else .{ .d = a.d + b.d };
    }
    pub fn square(a: @This()) @This() {
        return a.mul(a);
    }
    pub fn inv(_: @This()) @This() {
        @panic("inverse in raw fraction authority");
    }
};
pub fn emit(comptime F: type, origin: G.Role, fixed: []const F, main: []const F, epoch: F, public: A.word16_cpu.public.Public, sink: anytype) void {
    if (Table.kindForRole(origin)) |kind| {
        const shape = Table.mainShapeFor(kind);
        Table.emitLocalFor(kind, if (kind == .boundary) .{ .value = public, .cpu_log = 5 } else null, F, fixed[0..shape.fixed], main[0..shape.main], sink);
    } else |_| {
        if (origin != .initial and origin != .terminal) {
            const role = Role.mainRole(origin) catch unreachable;
            const shape = A.main_only.authority.shape(role);
            Role.emitLocalFor(F, role, fixed[0..shape.fixed], main[0..shape.main], epoch, sink);
        }
    }
}
fn build(role: G.Role) Plan {
    @setEvalBranchQuota(2000000);
    var out = Plan{ .terms = Roster.terms(role) };
    if (out.terms == 0) return out;
    const Sink = struct {
        plan: *Plan,
        at: usize = 0,
        pub fn emit(s: *@This(), _: Fn.Relation, tuple: anytype, weight: Degree) void {
            var degree: u8 = 0;
            for (tuple) |value| degree = @max(degree, value.d);
            s.plan.degree[s.at] = .{ .denominator = degree, .weight = weight.d };
            s.at += 1;
        }
    };
    const fixed = [_]Degree{.{ .d = 1 }} ** 34;
    const main = [_]Degree{.{ .d = 1 }} ** 128;
    var sink = Sink{ .plan = &out };
    emit(Degree, role, &fixed, &main, Degree.one(), std.mem.zeroes(A.word16_cpu.public.Public), &sink);
    if (sink.at != out.terms or out.terms > MAX_TERMS) @compileError("classic fraction degree catalog does not cover roster");
    var pending: ?u8 = null;
    for (out.degree[0..out.terms], 0..) |d, i| {
        if (d.denominator > 2 or d.weight > 2) @compileError("classic control requires degree-three raw fractions");
        if (d.denominator <= 1 and d.weight <= 1) {
            if (pending) |p| {
                out.groups[out.group_count] = .{ .first = p, .second = @intCast(i) };
                out.group_count += 1;
                pending = null;
            } else pending = @intCast(i);
        } else {
            out.groups[out.group_count] = .{ .first = @intCast(i) };
            out.group_count += 1;
        }
    }
    if (pending) |p| {
        out.groups[out.group_count] = .{ .first = p };
        out.group_count += 1;
    }
    if (out.group_count > MAX_GROUPS) @compileError("classic control group capacity exceeded");
    return out;
}
pub const CATALOG: [G.ROLE_COUNT]Plan = blk: {
    @setEvalBranchQuota(2000000);
    var result: [G.ROLE_COUNT]Plan = undefined;
    for (std.enums.values(G.Role), &result) |role, *p| p.* = build(role);
    break :blk result;
};
pub fn forRole(role: G.Role) *const Plan {
    return &CATALOG[@intFromEnum(role)];
}
