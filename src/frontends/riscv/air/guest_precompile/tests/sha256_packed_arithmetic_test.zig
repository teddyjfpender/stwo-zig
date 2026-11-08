const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../lang/mod.zig");
const packed_sha = @import("../sha256_packed_arithmetic.zig");
const program = @import("../sha256_word_program.zig");
const reference = @import("../sha256_compression.zig");
const support = @import("../../../recursion/air/test_support.zig");
const M = core.fields.m31.M31;
const tables = @import("../../lookups/tables/schema.zig");
fn check(comptime kind: program.Kind, d: *const packed_sha.Definition(kind), row: []const M, output: *[program.outputCount(kind)]u32) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &d.arena, row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |c| if (!values[lang.types.idIndex(c.root)].isZero()) return false;
    for (d.arena.effectsView(), 0..) |event, i| {
        const tuple = d.arena.effectValues(@enumFromInt(i)).?;
        var v: [4]u32 = undefined;
        for (tuple, 0..) |id, j| v[j] = values[lang.types.idIndex(id)].toU32();
        try std.testing.expectEqual(lang.relation.Role.request, event.binding.?.role);
        try std.testing.expectEqual(@as(u32, 1), values[lang.types.idIndex(event.liveness.?)].toU32());
        const schema = event.binding.?.schema;
        if (schema == lang.relation.id(.range_check_8_8)) {
            _ = tables.indexBase(.range_check_8_8, &.{ M.fromCanonical(v[0]), M.fromCanonical(v[1]) }) catch return false;
        } else if (schema == lang.relation.id(.bitwise)) {
            _ = tables.indexBase(.bitwise, &.{ M.fromCanonical(v[0]), M.fromCanonical(v[1]), M.fromCanonical(v[2]), M.fromCanonical(v[3]) }) catch return false;
        } else return error.UnexpectedShaRelation;
    }
    output.* = @splat(0);
    for (d.output, 0..) |word, i| for (word, 0..) |id, j| {
        output[i] |= values[lang.types.idIndex(id)].toU32() << @as(u5, @intCast(j * 8));
    };
    return true;
}
fn expected(comptime kind: program.Kind, x: [program.inputCount(kind)]u32) [program.outputCount(kind)]u32 {
    return switch (kind) {
        .round => blk: {
            const r = reference.round(x[0..8].*, x[8], x[9]);
            break :blk .{ r[0], r[4] };
        },
        .schedule => .{reference.sigmaSmall1(x[0]) +% x[1] +% reference.sigmaSmall0(x[2]) +% x[3]},
        .feed_forward => .{x[0] +% x[1]},
    };
}
test "SHA packed arithmetic matches independent semantics and rejects scratch and range mutations" {
    var rng = std.Random.DefaultPrng.init(0x736861323536);
    inline for (.{ program.Kind.round, .schedule, .feed_forward }) |kind| {
        var d = try packed_sha.build(kind, std.testing.allocator);
        defer d.deinit();
        var degree = try lang.degree.analyze(std.testing.allocator, &d.arena);
        defer degree.deinit();
        try std.testing.expect(degree.maximumConstraintDegree() <= 1);
        const digest = try lang.digest.computeIdentity(&d.arena);
        std.debug.print("SHA_PACKED kind={s} columns={d} constraints={d} lookups={d} digest={s}\n", .{ @tagName(kind), d.columns, d.arena.constraintsView().len, d.arena.effectsView().len, std.fmt.bytesToHex(digest.bytes, .lower) });
        for (0..80) |case| {
            var input: [program.inputCount(kind)]u32 = undefined;
            for (&input) |*x| x.* = switch (case) {
                0 => 0,
                1 => 0xffffffff,
                2 => 0x80000000,
                3 => 0x0000ffff,
                4 => 0xffff0000,
                else => rng.random().int(u32),
            };
            const row = try packed_sha.witness(kind, std.testing.allocator, input);
            defer std.testing.allocator.free(row);
            try std.testing.expectEqual(d.columns, row.len);
            var output: [program.outputCount(kind)]u32 = undefined;
            if (!try check(kind, &d, row, &output)) {
                std.debug.print("BAD_WITNESS kind={s} case={d}\n", .{ @tagName(kind), case });
                return error.InvalidGeneratedShaWitness;
            }
            try std.testing.expectEqualDeep(expected(kind, input), output);
            if (case == 5) for (row, 0..) |*value, coordinate| {
                const saved = value.*;
                defer value.* = saved;
                value.* = saved.add(M.one());
                if (try check(kind, &d, row, &output)) {
                    // SHA is not injective in every input bit (e.g. masked c
                    // bits in Maj). The caller wires those inputs separately.
                    // Every scratch coordinate, however, must be determined.
                    try std.testing.expect(coordinate < 4 * program.inputCount(kind));
                    try std.testing.expect(value.toU32() < 256);
                    var changed_input = input;
                    const shift: u5 = @intCast((coordinate % 4) * 8);
                    changed_input[coordinate / 4] = (changed_input[coordinate / 4] & ~(@as(u32, 255) << shift)) | (value.toU32() << shift);
                    try std.testing.expectEqualDeep(expected(kind, changed_input), output);
                }
                value.* = M.fromCanonical(256);
                if (!saved.eql(value.*)) try std.testing.expect(!try check(kind, &d, row, &output));
            };
        }
    }
}
test "SHA packed arithmetic follows every round and expansion of a compression" {
    var message: [64]u8 = undefined;
    for (&message, 0..) |*x, i| x.* = @truncate(i * 53 + 19);
    const trace = reference.witness(reference.initial_state, message);
    var round_def = try packed_sha.build(.round, std.testing.allocator);
    defer round_def.deinit();
    for (0..64) |i| {
        const row = try packed_sha.witness(.round, std.testing.allocator, trace.states[i] ++ .{ trace.schedule[i], reference.round_constants[i] });
        defer std.testing.allocator.free(row);
        var output: [2]u32 = undefined;
        try std.testing.expect(try check(.round, &round_def, row, &output));
        try std.testing.expectEqualDeep([2]u32{ trace.states[i + 1][0], trace.states[i + 1][4] }, output);
    }
    var schedule_def = try packed_sha.build(.schedule, std.testing.allocator);
    defer schedule_def.deinit();
    for (16..64) |i| {
        const w = trace.schedule;
        const row = try packed_sha.witness(.schedule, std.testing.allocator, .{ w[i - 2], w[i - 7], w[i - 15], w[i - 16] });
        defer std.testing.allocator.free(row);
        var output: [1]u32 = undefined;
        try std.testing.expect(try check(.schedule, &schedule_def, row, &output));
        try std.testing.expectEqual(w[i], output[0]);
    }
}
