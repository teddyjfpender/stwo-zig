const std = @import("std");
const E = @import("../evaluation.zig");
const Q = E.Q;
const Leaf = @import("leaf_air.zig");
const Side = @import("side_air.zig");
const Permit = @import("permit_air.zig");
const PR = @import("policy_provider.zig");
const PA = @import("policy_air.zig");
const internal = @import("internal_relations.zig");
const policy = @import("policy.zig");
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
const Kind = enum { leaf512, leaf4096, side512, side4096, permit8, permit512, permit4096, policy_rom };

test "RV64 private graph: every leaf side permission and policy-ROM residual has degree at most four over arbitrary QM31" {
    var raw = internal.Challenge{ .offset = sample(37), .coefficients = undefined };
    for (&raw.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(97 + i * 3));
    const ram = raw.prepare();
    var p = PA.PolicyChallenge{ .offset = sample(199), .coefficients = undefined };
    for (&p.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(307 + 5 * i));
    const kinds = [_]Kind{ .leaf512, .leaf4096, .side512, .side4096, .permit8, .permit512, .permit4096, .policy_rom };
    for (kinds) |kind| {
        const count: usize = switch (kind) {
            .leaf512, .leaf4096 => Leaf.CONSTRAINTS,
            .side512, .side4096 => Side.CONSTRAINTS,
            .permit8, .permit512, .permit4096 => Permit.CONSTRAINTS,
            .policy_rom => PR.CONSTRAINTS,
        };
        var evaluations: [6][63]Q = undefined;
        for (0..6) |step| {
            const t = E.q(@intCast(step));
            var main: [62]Q = undefined;
            var previous: [62]Q = undefined;
            var fixed: [21]Q = undefined;
            var current: [44]Q = undefined;
            var old: [44]Q = undefined;
            for (&main, &previous, 0..) |*field, *prior, i| {
                field.* = sample(@intCast(503 + i)).add(t.mul(sample(@intCast(601 + i))));
                prior.* = sample(@intCast(701 + i)).add(t.mul(sample(@intCast(809 + i))));
            }
            for (&fixed, 0..) |*field, i| field.* = sample(@intCast(907 + i)).add(t.mul(sample(@intCast(1009 + i))));
            for (&current, &old, 0..) |*field, *prior, i| {
                field.* = sample(@intCast(1103 + i)).add(t.mul(sample(@intCast(1201 + i))));
                prior.* = sample(@intCast(1301 + i)).add(t.mul(sample(@intCast(1409 + i))));
            }
            var sink = E.Sink{ .values = &evaluations[step] };
            switch (kind) {
                .leaf512, .leaf4096 => Leaf.evaluate(.{ .geometry = if (kind == .leaf512) .chunk512 else .page4096, .leaves = 1, .log_size = 4 }, fixed[0..Leaf.FIXED], main[0..Leaf.MAIN], previous[0..Leaf.MAIN], current[0..Leaf.INTERACTION], old[0..Leaf.INTERACTION], @splat(sample(43)), &.{ .ram = ram, .bytes = sample(47) }, &sink),
                .side512, .side4096 => Side.evaluate(.{ .geometry = if (kind == .side512) .chunk512 else .page4096, .sides = 1, .log_size = 4 }, fixed[0..Side.FIXED], main[0..Side.MAIN], previous[0..Side.MAIN], current[0..Side.INTERACTION], old[0..Side.INTERACTION], @splat(sample(53)), &.{ .ram = ram, .bytes = sample(59) }, &sink),
                .permit8, .permit512, .permit4096 => Permit.evaluate(.{ .span = switch (kind) {
                    .permit8 => policy.Span.word8,
                    .permit512 => .chunk512,
                    else => .page4096,
                }, .certificates = 1, .log_size = 4 }, fixed[0..Permit.FIXED], main[0..Permit.MAIN], previous[0..Permit.MAIN], current[0..Permit.INTERACTION], old[0..Permit.INTERACTION], @splat(sample(61)), &.{ .bytes = sample(67), .policy = p, .permit = ram.permitChallenge() }, &sink),
                .policy_rom => PR.evaluate(.{ .grants = &.{}, .log_size = 4 }, fixed[0..PR.FIXED], main[0..PR.MAIN], previous[0..PR.MAIN], current[0..PR.INTERACTION], old[0..PR.INTERACTION], @splat(sample(71)), &.{ .policy = p }, &sink),
            }
            try std.testing.expectEqual(count, sink.count);
        }
        for (0..5) |level| for (0..5 - level) |row| for (0..count) |column| {
            evaluations[row][column] = evaluations[row + 1][column].sub(evaluations[row][column]);
        };
        for (evaluations[0][0..count]) |residual| try std.testing.expect(residual.isZero());
    }
}
