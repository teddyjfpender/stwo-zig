//! Bulk v3 foundation only: no production admission or accepting execution.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.crypto.bulk_memory;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Projection = @import("bulk_projection.zig");
const Frame = @import("frame.zig");
fn value(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 719 + i * 79 + 3) % 65521));
    return O.fromM31Array(c);
}
fn classic(local: @import("challenges.zig").For(O)) B.types.ChallengesFor(O) {
    var out: B.types.ChallengesFor(O) = undefined;
    out.ram.offset = value(700);
    for (&out.ram.coefficients, 0..) |*c, i| c.* = value(721 + i);
    const owner = @intFromEnum(@import("fractions.zig").Relation.owner);
    out.owner.offset = local.offsets[owner];
    @memcpy(&out.owner.coefficients, local.coefficients[owner][0..19]);
    out.range16.offset = local.offsets[@intFromEnum(@import("fractions.zig").Relation.range16)];
    out.range16.coefficient = local.coefficients[@intFromEnum(@import("fractions.zig").Relation.range16)][0];
    return out;
}
const Compressed = struct {
    ch: B.types.ChallengesFor(O),
    fractions: [128]B.equations.Fraction(O) = undefined,
    count: usize = 0,
    pub fn emit(self: *@This(), _: @import("global_cpu.zig").Relation, tuple: anytype, weight: O) void {
        self.fractions[self.count] = .{ .d = self.ch.ram.denominatorFor(O, tuple), .w = weight, .relation = B.equations.RAM };
        self.count += 1;
    }
};
test "all nine bulk local projections and RAM debts match classic ordered fractions including padding" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = @import("challenges.zig").For(O).draw(&channel);
    const old_ch = classic(ch);
    inline for (comptime std.enums.values(B.layout.Kind)) |kind| {
        try std.testing.expectEqual(B.layout.fractionCount(kind), Projection.localTerms(kind) + Projection.ramTerms(kind));
        const metadata = @import("query_metadata.zig");
        try std.testing.expectEqual(Projection.localTerms(kind), metadata.sum(metadata.BULK[@intFromEnum(kind)]));
        for ([_]bool{ false, true }) |padding| {
            var fixed: [B.layout.fixedWidth(kind)]O = undefined;
            var main: [B.layout.main(kind)]O = undefined;
            for (&fixed, 0..) |*v, i| v.* = value(31 + i);
            for (&main, 0..) |*v, i| v.* = if (padding) O.zero() else value(101 + i);
            const expected = B.equations.fractions(O, kind, &fixed, &main, old_ch);
            const terms = Projection.localTerms(kind);
            const lanes: usize = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
            var weights: [128]O = undefined;
            for (&weights, 0..) |*v, i| v.* = value(501 + i);
            var actual = @import("binding.zig").ProjectionFor(O){ .challenges = &ch, .lane_weights = weights[0..lanes], .terms = terms };
            Projection.emitLocalFor(O, kind, &fixed, &main, &actual);
            try actual.finish();
            var ram = Compressed{ .ch = old_ch };
            Projection.emitGlobalFor(O, kind, &fixed, &main, &ram);
            var n = O.zero();
            var d = O.zero();
            var local_count: usize = 0;
            var ram_count: usize = 0;
            for (expected) |fraction| {
                if (fraction.relation == B.equations.RAM) {
                    try std.testing.expectEqualDeep(fraction, ram.fractions[ram_count]);
                    ram_count += 1;
                } else {
                    n = n.add(weights[local_count].mul(fraction.w));
                    d = d.add(weights[local_count].mul(fraction.d));
                    local_count += 1;
                }
            }
            for (weights[terms..lanes]) |w| d = d.add(w);
            try std.testing.expectEqual(terms, local_count);
            try std.testing.expectEqual(Projection.ramTerms(kind), ram_count);
            try std.testing.expectEqual(ram_count, ram.count);
            try std.testing.expectEqual(n, actual.numerator);
            try std.testing.expectEqual(d, actual.denominator);
        }
    }
}
test "bulk local binding and global RAM residuals fit degree three on full OM31 lines" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = @import("challenges.zig").For(O).draw(&channel);
    const old_ch = classic(ch);
    const shared = @import("manifest.zig").Shared{ .ram = old_ch.ram, .kio = undefined, .wire = undefined };
    const G = @import("global_cpu.zig");
    inline for (comptime std.enums.values(B.layout.Kind)) |kind| {
        const origin = Frame.Origin{ .bulk = kind };
        const l = G.layout(origin);
        const terms = Projection.localTerms(kind);
        const lanes: usize = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
        var weights: [128]O = undefined;
        for (&weights, 0..) |*v, i| v.* = value(501 + i);
        var samples: [5][16]O = undefined;
        for (0..5) |t| {
            const x = O.fromBase(M.fromCanonical(@intCast(t)));
            var fixed: [B.layout.fixedWidth(kind)]O = undefined;
            var main: [B.layout.main(kind)]O = undefined;
            var current: [80]O = undefined;
            var previous: [80]O = undefined;
            for (&fixed, 0..) |*v, i| v.* = value(31 + i).add(value(311 + i).mul(x));
            for (&main, 0..) |*v, i| v.* = value(101 + i).add(value(411 + i).mul(x));
            for (&current, &previous, 0..) |*v, *p, i| {
                v.* = value(701 + i).add(value(811 + i).mul(x));
                p.* = value(901 + i).add(value(1011 + i).mul(x));
            }
            var projection = @import("binding.zig").ProjectionFor(O){ .challenges = &ch, .lane_weights = weights[0..lanes], .terms = terms };
            Projection.emitLocalFor(O, kind, &fixed, &main, &projection);
            try projection.finish();
            samples[t][0] = projection.combine(value(991)).mul(value(111).add(value(123).mul(x)));
            var sink = A.evaluation.SinkFor(O){ .values = samples[t][1..] };
            if (l.width() != 0) try G.emitFor(O, origin, shared, .{ .ram = value(51), .kio = O.zero(), .wire = O.zero() }, &fixed, &main, current[0..l.width()], previous[0..l.width()], &sink);
            try std.testing.expectEqual(l.constraints(), sink.count);
        }
        for (0..3) |order| for (0..4 - order) |t| for (0..l.constraints() + 1) |i| {
            samples[t][i] = samples[t + 1][i].sub(samples[t][i]);
        };
        for (0..l.constraints() + 1) |i| try std.testing.expect(samples[1][i].sub(samples[0][i]).isZero());
    }
}
const Balanced = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, logical: usize, sink: *@import("inputs.zig").RowSink) !void {
        sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(logical))}, if (instance.origin.bulk == .set) M.one() else M.one().neg());
    }
};
test "v3 child framing authenticates role geometry offsets and order and refuses v2 replay" {
    const a = std.testing.allocator;
    const Child = @import("child.zig");
    const Wire = @import("wire.zig");
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .bulk = .set }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .bulk = .copy }, .row_log = 5, .terms = 1, .fixed_offset = 3, .main_offset = 47 },
    };
    // Synthetic balanced rows qualify framing, never the admitted role roster.
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const child = try Child.Unbound.prove(a, 1 << 20, scope, &instances, Balanced{});
    defer child.deinit();
    const bytes = try Wire.encode(a, &instances, &child.result.proof);
    defer a.free(bytes);
    try std.testing.expectEqualStrings(Wire.V3_MAGIC, bytes[0..8]);
    var decoded = try Wire.decode(a, &instances, bytes);
    defer decoded.deinit();
    var pending = try Child.verifyPending(a, scope, &instances, &decoded.proof, child.digest);
    defer pending.deinit(a);
    for (0..6) |mutation| {
        var changed = instances;
        switch (mutation) {
            0 => changed[0].origin = .{ .bulk = .desc },
            1 => changed[0].row_log += 1,
            2 => changed[0].terms += 1,
            3 => changed[0].fixed_offset += 1,
            4 => changed[0].main_offset += 1,
            5 => std.mem.swap(Frame.Instance, &changed[0], &changed[1]),
            else => unreachable,
        }
        if (Child.verifyPending(a, scope, &changed, &decoded.proof, child.digest)) |ok| {
            var unexpected = ok;
            unexpected.deinit(a);
            return error.ChangedFramingAccepted;
        } else |_| {}
    }
    var v2 = instances;
    v2[0].origin = .{ .core = .alu };
    v2[1].origin = .{ .core = .binary };
    try std.testing.expectError(error.LocalGkrWireProfile, Wire.decode(a, &v2, bytes));
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    @memcpy(bad[0..8], Wire.MAGIC);
    try std.testing.expectError(error.LocalGkrWireProfile, Wire.decode(a, &instances, bad));
    try std.testing.expectEqual([2]u32{ 0, 0 }, Frame.originWords(.{ .core = .cpu }));
    try std.testing.expectEqual([2]u32{ 1, 0 }, Frame.originWords(.{ .bridge = .keccak }));
    try std.testing.expectEqual([2]u32{ 2, @intFromEnum(B.layout.Kind.set) }, Frame.originWords(.{ .bulk = .set }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, @import("v2_scope.zig").bridges(.{ .bulk = .{ .set = 5 } }));
}
