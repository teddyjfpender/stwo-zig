const std = @import("std");
const core = @import("stwo_core");
const canonical_lang_eab98d = @import("stwo_riscv_air_lang").degree;
const canonical_lang_2ce8fd = @import("stwo_riscv_air_lang").digest;
const canonical_lang_54a539 = @import("stwo_riscv_air_lang").relation;
const canonical_lang_3c1a7c = @import("stwo_riscv_air_lang").types;
const packed_sha = @import("stwo_riscv_precompiles").air.sha256_packed_arithmetic;
const program = @import("stwo_riscv_precompiles").air.sha256_word_program;
const reference = @import("stwo_riscv_precompiles").air.sha256_compression;
const support = @import("stwo_riscv_recursion_air").testing.test_support;
const M = core.fields.m31.M31;
const tables = @import("stwo_riscv_air_lang").evaluation.lookups.tables.schema;
fn check(comptime kind: program.Kind, d: *const packed_sha.Definition(kind), row: []const M, output: *[program.outputCount(kind)]u32) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &d.arena, row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |c| if (!values[canonical_lang_3c1a7c.idIndex(c.root)].isZero()) return false;
    for (d.arena.effectsView(), 0..) |event, i| {
        const tuple = d.arena.effectValues(@enumFromInt(i)).?;
        var v: [4]u32 = undefined;
        for (tuple, 0..) |id, j| v[j] = values[canonical_lang_3c1a7c.idIndex(id)].toU32();
        try std.testing.expectEqual(canonical_lang_54a539.Role.request, event.binding.?.role);
        try std.testing.expectEqual(@as(u32, 1), values[canonical_lang_3c1a7c.idIndex(event.liveness.?)].toU32());
        const schema = event.binding.?.schema;
        if (schema == canonical_lang_54a539.id(.range_check_8_8)) {
            _ = tables.indexBase(.range_check_8_8, &.{ M.fromCanonical(v[0]), M.fromCanonical(v[1]) }) catch return false;
        } else if (schema == canonical_lang_54a539.id(.bitwise)) {
            _ = tables.indexBase(.bitwise, &.{ M.fromCanonical(v[0]), M.fromCanonical(v[1]), M.fromCanonical(v[2]), M.fromCanonical(v[3]) }) catch return false;
        } else return error.UnexpectedShaRelation;
    }
    output.* = @splat(0);
    for (d.output, 0..) |word, i| for (word, 0..) |id, j| {
        output[i] |= values[canonical_lang_3c1a7c.idIndex(id)].toU32() << @as(u5, @intCast(j * 8));
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
        var degree = try canonical_lang_eab98d.analyze(std.testing.allocator, &d.arena);
        defer degree.deinit();
        try std.testing.expect(degree.maximumConstraintDegree() <= 1);
        const digest = try canonical_lang_2ce8fd.computeIdentity(&d.arena);
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
