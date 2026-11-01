//! Benchmark-only MAIN authority + classic local LogUp + original RAM debt.
//! One physical MAIN span per role; no GKR witnesses or synthetic zero child.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const CP = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Main = A.main_only.authority;
const G = @import("../../../../word16_execution/geometry.zig");
const Request = @import("../../protocol.zig").Request;
const Table = @import("../../gkr_local/table_role.zig");
const Role = @import("../../gkr_local/role.zig");
const Boundary = @import("../../gkr_local/boundary_role.zig");
const Global = @import("../../gkr_local/global_cpu.zig");
const Manifest = @import("../../gkr_local/manifest.zig");
const Ch = @import("../../gkr_local/challenges.zig").For(O);
const Fn = @import("../../gkr_local/fractions.zig");
const Policy = @import("policy.zig");
pub const Public = union(enum) { arithmetic: Main.PublicFor(O), table: struct { kind: Table.Kind, boundary: ?Table.Boundary }, boundary: u32 };
pub fn publicFor(role: G.Role, geometry: G.Geometry, r: Request) !Public {
    if (role == .initial or role == .terminal) return .{ .boundary = @intCast(if (role == .initial) r.base.memory.initial.len else r.base.memory.terminal.len) };
    if (Table.kindForRole(role)) |kind| return .{ .table = .{ .kind = kind, .boundary = if (role == .boundary) .{ .value = r.base.cpu, .cpu_log = geometry.cpu_log } else null } } else |_| {}
    const counts = try geometry.lsCounts(r.base.memory.ls_count);
    const public: Main.PublicFor(O) = switch (role) {
        .cpu => blk: {
            const v = try A.word16_execution.types.inputs(r.base.cpu, r.base.epoch, geometry.cpu_log);
            break :blk .{ .cpu = .{ .steps = v.steps, .initial_pc = v.initial_pc, .final_pc = v.final_pc, .epoch = v.epoch } };
        },
        .alu, .alu_tail => .{ .alu = {} },
        .binary, .binary_tail => .{ .binary = {} },
        .shift, .shift_tail => .{ .shift = {} },
        .jalr => .{ .jalr = {} },
        .division => .{ .div = .{ .count = r.base.division_requests } },
        .multiplication => .{ .mul = .{ .count = r.base.multiplication_requests } },
        .ls => .{ .ls = .{ .count = counts.head } },
        .ls_tail => .{ .ls = .{ .count = counts.tail } },
        else => return error.InvalidClassicControlRole,
    };
    return .{ .arithmetic = public };
}
fn anchors(role: G.Role) [2]usize {
    return switch (role) {
        .rom => .{ A.word16_execution.layout.rom.FIRST, A.word16_execution.layout.rom.LAST },
        .boundary => .{ 32, 33 },
        .alu, .alu_tail, .binary, .binary_tail, .shift, .shift_tail, .jalr => .{ 0, 1 },
        .shift_table => .{ 16, 17 },
        .and_table => .{ 3, 4 },
        .selection => .{ 4, 5 },
        else => .{ 1, 2 },
    };
}
pub const Component = struct {
    pub const LOCAL_GKR = false;
    pub const MAX_FIXED = 34;
    pub const MAX_MAIN = 128;
    pub const MAX_INTER = 8 * (Policy.MAX_GROUPS + 1) + 16;
    role: G.Role,
    log: u32,
    source_fixed: usize,
    offsets: [2]usize,
    inter_offset: usize,
    epoch: u16,
    public: Public,
    register_public: A.word16_cpu.public.Public,
    challenges: Ch,
    shared: Manifest.Shared,
    local_claim: O,
    global_claims: Global.ClaimsFor(O),
    pub fn logSize(self: *const @This()) u32 {
        return self.log;
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    fn usedShape(self: *const @This()) Main.Shape {
        return switch (self.public) {
            .arithmetic => |p| Main.shape(std.meta.activeTag(p)),
            .table => |p| Table.mainShapeFor(p.kind),
            .boundary => Boundary.MAIN_SHAPE,
        };
    }
    pub fn mainShape(self: *const @This()) Main.Shape {
        var s = self.usedShape();
        s.fixed = self.source_fixed;
        return s;
    }
    pub fn previousMain(self: *const @This(), c: usize) bool {
        return switch (self.public) {
            .arithmetic => |p| Main.previousMain(std.meta.activeTag(p), c),
            .boundary => c == 0,
            .table => false,
        };
    }
    pub fn interWidth(self: *const @This()) usize {
        return Policy.forRole(self.role).width() + Global.layout(.{ .core = self.role }).width();
    }
    pub fn previousInter(self: *const @This(), c: usize) bool {
        const w = Policy.forRole(self.role).width();
        return if (c < w) c >= w - 8 else Global.layout(.{ .core = self.role }).previous(c - w);
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const f = fixed[0..self.usedShape().fixed];
        switch (self.public) {
            .arithmetic => |p| try Main.emitFor(F, p, f, main, previous, sink),
            .table => |p| try Table.emitMainFor(p.kind, F, f, main, previous, sink),
            .boundary => |count| A.memory.load_store_v2.equations.emitBoundaryMainFor(F, f, main, previous, E.qFor(F, count), E.qFor(F, @intFromBool(count != 0)), sink),
        }
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const p = Policy.forRole(self.role);
        const S = E.SecureFor(F);
        if (p.terms != 0) {
            const Collector = struct {
                ch: *const Ch,
                denominators: [Policy.MAX_TERMS]S = undefined,
                weights: [Policy.MAX_TERMS]F = undefined,
                count: usize = 0,
                pub fn emit(s: *@This(), relation: Fn.Relation, tuple: anytype, w: F) void {
                    s.denominators[s.count] = s.ch.denominatorFor(F, relation, tuple);
                    s.weights[s.count] = w;
                    s.count += 1;
                }
            };
            var raw = Collector{ .ch = &self.challenges };
            Policy.emit(F, self.role, fixed, main, E.qFor(F, self.epoch), self.register_public, &raw);
            if (raw.count != p.terms) return error.ClassicControlFractionShape;
            var contribution = S.zero();
            for (p.groups[0..p.group_count], 0..) |g, i| {
                const inverse = E.secureForField(O, F, current, 8 * i);
                const denominator = raw.denominators[g.first];
                if (g.second) |j| {
                    const other = raw.denominators[j];
                    sink.emit(denominator.mul(other).mul(inverse).sub(S.one()));
                    const numerator = E.mulBaseFor(F, other, raw.weights[g.first]).add(E.mulBaseFor(F, denominator, raw.weights[j]));
                    contribution = contribution.add(inverse.mul(numerator));
                } else {
                    sink.emit(denominator.mul(inverse).sub(S.one()));
                    contribution = contribution.add(E.mulBaseFor(F, inverse, raw.weights[g.first]));
                }
            }
            const idx = anchors(self.role);
            const sum = E.secureForField(O, F, current, 8 * p.group_count);
            const prev = E.secureForField(O, F, previous, 8 * p.group_count);
            sink.emit(sum.sub(prev).add(E.mulBaseFor(F, E.splatFor(F, self.local_claim), fixed[idx[0]])).sub(contribution));
            sink.emit(E.mulBaseFor(F, sum, fixed[idx[1]]));
        }
        const w = p.width();
        try Global.emitFor(F, .{ .core = self.role }, self.shared, self.global_claims, fixed, main, current[w..], previous[w..], sink);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.usedShape().constraints + Policy.forRole(self.role).constraints() + Global.layout(.{ .core = self.role }).constraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), i: usize) !u8 {
        if (i >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn validate(self: *const @This()) !void {
        if (self.log < 5 or self.log > 22 or self.source_fixed > MAX_FIXED or self.interWidth() > MAX_INTER) return error.InvalidClassicControlRole;
        try Global.validateClaims(.{ .core = self.role }, self.global_claims);
        switch (self.public) {
            .arithmetic => |p| {
                if ((try Role.mainRole(self.role)) != std.meta.activeTag(p)) return error.InvalidClassicControlRole;
            },
            .table => |p| {
                if ((try Table.kindForRole(self.role)) != p.kind or ((p.kind == .boundary) != (p.boundary != null))) return error.InvalidClassicControlRole;
                if (p.boundary) |b| try b.value.validate(b.cpu_log);
            },
            .boundary => |count| {
                if ((self.role != .initial and self.role != .terminal) or count >= @as(u32, 1) << @intCast(self.log)) return error.InvalidClassicControlRole;
            },
        }
        if (Policy.forRole(self.role).terms == 0 and !self.local_claim.isZero()) return error.NonzeroAbsentClassicControlClaim;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return @import("../../gkr_local/role_geometry.zig").bounds(self, a);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return @import("../../gkr_local/role_geometry.zig").indices(self, a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, log: u32) !Air.MaskPoints {
        return @import("../../gkr_local/role_geometry.zig").masks(self, a, point, log);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, log: u32) !void {
        return @import("../../gkr_local/role_oods.zig").evaluate(self, point, mask, acc, log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const CP.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("../../gkr_local/role_domain.zig").evaluate(self, trace, acc, null);
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), CP.ComponentProver, CP.Trace, D.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) CP.ComponentProver {
        return Adapter.asProverComponent(self);
    }
};
