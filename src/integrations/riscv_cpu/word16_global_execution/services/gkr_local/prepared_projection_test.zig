const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
const B = @import("binding.zig");
const P = @import("prepared_projection.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn check(comptime F: type) !void {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = @import("challenges.zig").For(O).draw(&channel);
    var weights: [16]O = undefined;
    for (&weights) |*w| w.* = channel.drawSecureFelt();
    var packed_weights: [16]E.SecureFor(F) = undefined;
    for (&packed_weights, weights) |*w, x| w.* = E.splatFor(F, x);
    const relations = comptime std.enums.values(R.Relation);
    var prepared = try P.For(F).init(a, relations, &ch, &weights);
    defer prepared.deinit();
    for (0..19) |iteration| {
        var original = B.ProjectionFor(F){ .challenges = &ch, .lane_weights = &packed_weights, .terms = relations.len };
        var fast = prepared.projection();
        for (relations, 0..) |relation, index| {
            var tuple: [R.MAX_ARITY]F = undefined;
            for (tuple[0..relation.arity()], 0..) |*v, c| {
                if (F == O) v.* = channel.drawSecureFelt() else {
                    var lanes: [E.LANES]M = undefined;
                    for (&lanes, 0..) |*lane, i| lane.* = M.fromCanonical(@intCast((iteration * 997 + index * 367 + c * 89 + i * 17) % 65536));
                    v.* = F.fromLanes(lanes);
                }
            }
            const weight = if (F == O) channel.drawSecureFelt() else F.fromBase(M.fromCanonical(@intCast((iteration + index) % 7)));
            original.emit(relation, tuple[0..relation.arity()], weight);
            fast.emit(relation, tuple[0..relation.arity()], weight);
        }
        try original.finish();
        try fast.finish();
        const eta = E.splatFor(F, channel.drawSecureFelt());
        if (F == O) {
            try std.testing.expect(original.numerator.eql(fast.numerator));
            try std.testing.expect(original.denominator.eql(fast.denominator));
            try std.testing.expect(original.combine(eta).eql(fast.combine(eta)));
        } else for (0..E.LANES) |lane| {
            try std.testing.expect(original.numerator.lane(lane).eql(fast.numerator.lane(lane)));
            try std.testing.expect(original.denominator.lane(lane).eql(fast.denominator.lane(lane)));
            try std.testing.expect(original.combine(eta).lane(lane).eql(fast.combine(eta).lane(lane)));
        }
    }
}
test "hoisted projection equals original all namespaces on native OODS and packed random rows" {
    try check(O);
    try check(E.PackedFields.BaseForField(O));
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = @import("challenges.zig").For(O).draw(&channel);
    var weights: [16]O = undefined;
    for (&weights) |*w| w.* = channel.drawSecureFelt();
    var prepared = try P.For(E.PackedFields.BaseForField(O)).init(allocator, std.enums.values(R.Relation), &ch, &weights);
    defer prepared.deinit();
    try std.testing.expect(prepared.bytes() <= P.MAX_PREPARED_BYTES);
}
test "prepared projection bounded owner releases every allocator failure" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}

test "metadata projection mode equals original terminal form in every namespace with padding and signed weights" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = @import("challenges.zig").For(O).draw(&channel);
    const relations = comptime std.enums.values(R.Relation);
    var weights: [16]O = undefined;
    for (&weights) |*w| w.* = channel.drawSecureFelt();
    var prepared = try P.For(O).init(a, relations, &ch, &weights);
    defer prepared.deinit();
    for (0..17) |row| {
        var original = B.ProjectionFor(O){ .challenges = &ch, .lane_weights = &weights, .terms = relations.len };
        var projected = prepared.projection();
        var sink = @import("inputs.zig").RowSink{ .challenges = &ch, .projection = &projected };
        inline for (relations, 0..) |relation, index| {
            const arity = comptime relation.arity();
            var tuple: [arity]M = undefined;
            var secure: [arity]O = undefined;
            for (&tuple, &secure, 0..) |*v, *s, j| {
                v.* = M.fromCanonical(@intCast((row * 997 + index * 367 + j * 89) % 65536));
                s.* = O.fromBase(v.*);
            }
            const weight = if ((row + index) % 3 == 0) M.zero() else M.fromCanonical(@intCast((row + index) % 19)).neg();
            original.emit(relation, secure, O.fromBase(weight));
            if (row % 2 == 0) sink.emitBase(relation, tuple, weight) else sink.emit(relation, secure, O.fromBase(weight));
        }
        try original.finish();
        try projected.finish();
        try std.testing.expect(!sink.invalid and sink.count == relations.len);
        try std.testing.expectEqual(original.numerator, projected.numerator);
        try std.testing.expectEqual(original.denominator, projected.denominator);
    }
    var projection = prepared.projection();
    var bad = @import("inputs.zig").RowSink{ .challenges = &ch, .projection = &projection };
    var noncanonical = [_]M{M.zero()} ** 30;
    noncanonical[0].v = core.fields.m31.Modulus;
    bad.emitBase(relations[0], noncanonical[0..relations[0].arity()], M.one());
    try std.testing.expect(bad.invalid);
}
