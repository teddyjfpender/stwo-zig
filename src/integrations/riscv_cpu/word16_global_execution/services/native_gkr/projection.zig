//! Raw native-v2 terminal marginals. Shared by native AIR, symbolic lowering
//! and circuit evaluation: no inverse or classic fraction packing belongs here.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = @import("roster.zig");
const Global = @import("../gkr_local/global_cpu.zig");
const Authority = @import("../gkr_local/constraint_authority.zig");
pub const LOCAL_RELATIONS = 10;

/// Each local namespace draws z, alpha after the section salt. Compression is
/// exactly z - sum_i alpha^i * tuple[i], including the constant coefficient 1.
pub fn LocalFor(comptime C: type) type {
    return struct {
        z: [LOCAL_RELATIONS]C,
        alpha: [LOCAL_RELATIONS]C,
        pub fn denominatorFor(self: *const @This(), comptime F: type, relation: anytype, tuple: anytype) E.SecureFor(F) {
            const Relation = if (@typeInfo(@TypeOf(relation)) == .enum_literal) (if (@hasField(@import("../gkr_local/fractions.zig").Relation, @tagName(relation))) @import("../gkr_local/fractions.zig").Relation else @import("../gkr_local/truth_fractions.zig").Relation) else @TypeOf(relation);
            const typed: Relation = relation;
            const index = @intFromEnum(typed);
            std.debug.assert(index < LOCAL_RELATIONS and tuple.len == typed.arity());
            var value = E.splatFor(F, self.z[index]);
            var power = C.one();
            for (tuple) |coordinate| {
                value = value.sub(E.mulBaseFor(F, E.splatFor(F, power), coordinate));
                power = power.mul(self.alpha[index]);
            }
            return value;
        }
    };
}

pub fn ProjectionFor(comptime F: type) type {
    const C = E.ConstFor(F);
    const S = E.SecureFor(F);
    return struct {
        const Self = @This();
        local: *const LocalFor(C),
        shared: *const Authority.SharedFor(C),
        /// Receiver-derived component term census, in local/RAM/KIO/Wire order.
        terms: [R.KINDS]u32,
        /// rho_g * eq(z_lane,g,lane), one independent rho for each present kind.
        weights: [R.KINDS][]const S,
        used: [R.KINDS]usize = @splat(0),
        invalid: bool = false,
        numerator: S = .zero(),
        denominator: S = .zero(),

        fn append(self: *@This(), kind: R.Kind, denominator: S, weight: F) void {
            const k = @intFromEnum(kind);
            const at = self.used[k];
            if (at >= self.terms[k] or at >= self.weights[k].len) {
                self.invalid = true;
                return;
            }
            self.used[k] += 1;
            const lane_weight = self.weights[k][at];
            self.numerator = self.numerator.add(E.mulBaseFor(F, lane_weight, weight));
            self.denominator = self.denominator.add(lane_weight.mul(denominator));
        }
        pub const LocalSink = struct {
            projection: *Self,
            pub fn emit(self: *@This(), relation: @import("../gkr_local/fractions.zig").Relation, tuple: anytype, weight: F) void {
                self.projection.emitLocal(relation, tuple, weight);
            }
        };
        pub const TruthSink = struct {
            projection: *Self,
            pub fn emit(self: *@This(), relation: @import("../gkr_local/truth_fractions.zig").Relation, tuple: anytype, weight: F) void {
                self.projection.emitLocal(relation, tuple, weight);
            }
        };
        pub fn truthSink(self: *Self) TruthSink {
            return .{ .projection = self };
        }
        pub const GlobalSink = struct {
            projection: *Self,
            pub fn emit(self: *@This(), relation: Global.Relation, tuple: anytype, weight: F) void {
                self.projection.emitGlobal(relation, tuple, weight);
            }
        };
        pub fn localSink(self: *Self) LocalSink {
            return .{ .projection = self };
        }
        pub fn globalSink(self: *Self) GlobalSink {
            return .{ .projection = self };
        }
        pub fn emitLocal(self: *@This(), relation: anytype, tuple: anytype, weight: F) void {
            self.append(.local, self.local.denominatorFor(F, relation, tuple), weight);
        }
        pub fn emitGlobal(self: *@This(), relation: Global.Relation, tuple: anytype, weight: F) void {
            const denominator = switch (relation) {
                .ram => E.denominatorFor(F, self.shared.ram.offset, &self.shared.ram.coefficients, &tuple, true),
                .kio => E.denominatorFor(F, self.shared.kio.offset, &self.shared.kio.coefficients, &tuple, true),
                .wire => E.denominatorFor(F, self.shared.wire.offset, &self.shared.wire.coefficients, &tuple, true),
            };
            self.append(switch (relation) {
                .ram => .ram,
                .kio => .kio,
                .wire => .wire,
            }, denominator, weight);
        }
        pub fn finish(self: *@This()) !void {
            if (self.invalid) return error.NativeGkrProjectionShape;
            for (self.terms, self.used, self.weights) |terms, used, weights| {
                if (used != terms) return error.NativeGkrEmitterTermCount;
                if (terms == 0) {
                    if (weights.len != 0) return error.NativeGkrProjectionShape;
                    continue;
                }
                if (weights.len != (@as(usize, 1) << @intCast(R.laneLog(terms)))) return error.NativeGkrProjectionShape;
                // Every padded fact is exactly (0,1), even when an original
                // real fact has zero numerator or a denominator pole.
                for (weights[terms..]) |weight| self.denominator = self.denominator.add(weight);
            }
        }
        pub fn combine(self: *const @This(), gamma: S) S {
            return self.numerator.add(gamma.mul(self.denominator));
        }
    };
}

const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
fn scalar(v: u32) O {
    return O.fromBase(M.fromCanonical(v));
}
test "native v2 raw terminal projection preserves poles and every padded kind" {
    const LR = @import("../gkr_local/fractions.zig").Relation;
    var local = LocalFor(O){ .z = @splat(scalar(101)), .alpha = @splat(scalar(3)) };
    local.z[@intFromEnum(LR.range8)] = scalar(13);
    var shared: Authority.SharedFor(O) = undefined;
    inline for (std.meta.fields(@TypeOf(shared))) |field| {
        @field(shared, field.name).offset = scalar(103);
        for (&@field(shared, field.name).coefficients, 0..) |*v, i| v.* = scalar(@intCast(i + 2));
    }
    const lw = [_]O{ scalar(2), scalar(3), scalar(5), scalar(7) };
    const rw = [_]O{scalar(11)};
    const kw = [_]O{scalar(13)};
    var projection = ProjectionFor(O){ .local = &local, .shared = &shared, .terms = .{ 3, 1, 1, 0 }, .weights = .{ &lw, &rw, &kw, &.{} } };
    var ls = projection.localSink();
    var gs = projection.globalSink();
    const t0 = [_]O{scalar(11)};
    const t1 = [_]O{scalar(13)};
    const t2 = [_]O{ O.one(), scalar(2), O.zero(), O.one() };
    ls.emit(LR.range16, t0, scalar(2));
    ls.emit(LR.range8, t1, O.zero()); // real zero/zero, never padded0/1
    ls.emit(LR.byte_pair, t2, O.one());
    const ram = [_]O{O.one()} ** @typeInfo(@TypeOf(shared.ram.coefficients)).array.len;
    const kio = [_]O{O.one()} ** @typeInfo(@TypeOf(shared.kio.coefficients)).array.len;
    gs.emit(.ram, ram, O.one());
    gs.emit(.kio, kio, O.one().neg());
    try projection.finish();
    var rd = shared.ram.offset;
    for (shared.ram.coefficients) |v| rd = rd.sub(v);
    var kd = shared.kio.offset;
    for (shared.kio.coefficients) |v| kd = kd.sub(v);
    var bd = local.z[@intFromEnum(LR.byte_pair)];
    var power = O.one();
    for (t2) |v| {
        bd = bd.sub(power.mul(v));
        power = power.mul(scalar(3));
    }
    const expected_d = scalar(2).mul(scalar(101 - 11)).add(scalar(5).mul(bd)).add(scalar(7)).add(scalar(11).mul(rd)).add(scalar(13).mul(kd));
    try std.testing.expect(projection.numerator.eql(scalar(7)));
    try std.testing.expect(projection.denominator.eql(expected_d));
    try std.testing.expect(projection.combine(scalar(19)).eql(scalar(7).add(scalar(19).mul(expected_d))));
    var wrong = projection;
    wrong.terms[0] = 4;
    try std.testing.expectError(error.NativeGkrEmitterTermCount, wrong.finish());
    wrong = projection;
    wrong.weights[3] = &rw;
    try std.testing.expectError(error.NativeGkrProjectionShape, wrong.finish());
}
