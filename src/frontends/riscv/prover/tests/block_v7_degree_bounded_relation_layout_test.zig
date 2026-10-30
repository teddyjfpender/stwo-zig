//! Opt-in geometry/algebra gates; no original or recursive proof qualification.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const Selected = @import("../block_v7_degree_bounded_relation_layout_v1.zig");
const Canonical = @import("../block_v7_native_relation_layout_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Universal = @import("../../recursion/air/universal_challenges.zig").UniversalRelations;
fn shapeFor(family: Opcode.OpcodeFamily) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = family, .log_size = 1, .n_rows = 1, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}

test "degree-bounded v7 covers every canonical opcode relation and original partition weight" {
    const a = std.testing.allocator;
    for (0..Opcode.N_FAMILIES) |ordinal| {
        for ([_]bool{ false, true }) |local_zero| {
            var shape = shapeFor(@enumFromInt(ordinal));
            if (local_zero) {
                shape.x0_local_custody_version = @import("../../air/x0_local_custody_v1.zig").VERSION;
                shape.component_descs[0].n_columns = @intCast(try @import("../../air/x0_native_envelope_v1.zig").mainColumnCount(@enumFromInt(ordinal)));
            }
            var original = try Canonical.Layout.init(a, &shape, 0, 1);
            defer original.deinit();
            var selected = try Selected.Layout.init(a, &shape, 0, 1);
            defer selected.deinit();
            try Selected.requireCoverage(a, &shape, 0, 1, selected.slots);
            var default_layout = try @import("../block_v7_native_layout_selection_v1.zig").derive(a, &shape, 0, .canonical_v1);
            defer default_layout.deinit();
            try std.testing.expectEqualDeep(original.slots, default_layout.slots);
            try std.testing.expectEqualDeep(original.digest, default_layout.digest);
            try std.testing.expect(!std.meta.eql(original.digest, selected.digest));
            try std.testing.expectEqual(original.slots.len + selected.split_pairs, selected.slots.len);
            try std.testing.expectEqual(@as(u32, 2), Fused.compositionSplit(selected.slots));
            // Compare at arbitrary extension-field points AND zero witnesses. The
            // equality of the combined numerator/denominator holds even where
            // rational evaluation is undefined; division is never used there.
            for (0..6) |seed| {
                var universal = Universal.dummy();
                if (seed >= 3) for (&universal.elements) |*element| {
                    const z = if (seed == 3) Q.zero() else Q.fromU32Unchecked(17, 23, 29, 31);
                    const alpha = if (seed <= 4) Q.zero() else Q.fromU32Unchecked(7, 11, 13, 19);
                    element.* = @TypeOf(element.*).init(element.arity, z, alpha);
                };
                var row: [Opcode.MAX_FAMILY_COLUMNS + 6]Q = undefined;
                for (&row, 0..) |*value, i| value.* = if (seed == 0 or seed == 3) Q.zero() else Q.fromU32Unchecked(@intCast(i + seed), @intCast(3 * i + 1), @intCast(seed + 5), 11);
                var at: usize = 0;
                for (original.slots) |slot| {
                    if (slot.degree <= 4) {
                        try std.testing.expectEqualDeep(slot, selected.slots[at]);
                        at += 1;
                        continue;
                    }
                    const first = selected.slots[at];
                    const second = selected.slots[at + 1];
                    try std.testing.expectEqual(@as(u8, 1), first.kind.lookup.entry_count);
                    try std.testing.expectEqual(@as(u8, 1), second.kind.lookup.entry_count);
                    try std.testing.expectEqual(slot.kind.lookup.entries[0], first.kind.lookup.entries[0]);
                    try std.testing.expectEqual(slot.kind.lookup.entries[1], second.kind.lookup.entries[0]);
                    const old = try Source.fromCommittedMain(slot, row[0..slot.width], &universal);
                    const left = try Source.fromCommittedMain(first, row[0..first.width], &universal);
                    const right = try Source.fromCommittedMain(second, row[0..second.width], &universal);
                    const denominator = left.denominator().mul(right.denominator());
                    const numerator = left.numerator().mul(right.denominator()).add(right.numerator().mul(left.denominator()));
                    try std.testing.expectEqualDeep(old.denominator(), denominator);
                    try std.testing.expectEqualDeep(old.numerator(), numerator);
                    if (!denominator.isZero()) {
                        const expected = old.numerator().mul(try old.denominator().inv());
                        const actual = left.numerator().mul(try left.denominator().inv()).add(right.numerator().mul(try right.denominator().inv()));
                        try std.testing.expectEqualDeep(expected, actual);
                        if (seed == 0) try std.testing.expect(expected.isZero());
                    } else {
                        try std.testing.expectError(error.DivisionByZero, old.denominator().inv());
                        try std.testing.expect(left.denominator().isZero() or right.denominator().isZero());
                    }
                    at += 2;
                }
                try std.testing.expectEqual(selected.slots.len, at);
            }
            const changed = try a.dupe(Source.Slot, selected.slots);
            defer a.free(changed);
            changed[changed.len - 1] = changed[0];
            try std.testing.expectError(error.InvalidDegreeBoundedCoverage, Selected.requireCoverage(a, &shape, 0, 1, changed));
            try std.testing.expectError(error.InvalidDegreeBoundedCoverage, Selected.requireCoverage(a, &shape, 0, 1, selected.slots[1..]));
        }
    }
}

test "degree-bounded MUL adds exactly two claims and eight interaction columns for q2" {
    const a = std.testing.allocator;
    var shape = shapeFor(.mul);
    shape.component_descs[0].log_size = 3;
    shape.component_descs[0].n_rows = 8;
    shape.total_steps = 8;
    shape.public_data.clock = 8;
    var original = try Canonical.Layout.init(a, &shape, 0, 1);
    defer original.deinit();
    var selected = try Selected.Layout.init(a, &shape, 0, 1);
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 2), selected.split_pairs);
    try std.testing.expectEqual(@as(u32, 3), Fused.compositionSplit(original.slots));
    try std.testing.expectEqual(@as(u32, 2), Fused.compositionSplit(selected.slots));
    try std.testing.expectEqual(@as(usize, 64), selected.split_pairs * 4 * 8);
    var split_index: usize = 0;
    const expected = [_][2]u8{ .{ 9, 10 }, .{ 11, 12 } };
    for (original.slots) |slot| if (slot.degree > 4) {
        try std.testing.expectEqual(@as(u8, 5), slot.degree);
        try std.testing.expectEqual(.range_check_8_11, slot.kind.lookup.partition);
        try std.testing.expectEqualDeep(expected[split_index], slot.kind.lookup.entries);
        split_index += 1;
    };
    try std.testing.expectEqual(expected.len, split_index);
    try std.testing.expectError(error.InvalidDegreeBoundedCoverage, Selected.requireCoverage(a, &shape, 0, 1, original.slots));
    const changed = try a.dupe(Source.Slot, selected.slots);
    defer a.free(changed);
    for (selected.slots, 0..) |slot, i| {
        if (slot.kind != .lookup) continue;
        inline for (.{ "degree", "entry_count", "main_offset", "width", "register_custody_mode" }) |field| {
            @memcpy(changed, selected.slots);
            @field(changed[i].kind.lookup, field) += 1;
            try std.testing.expectError(error.InvalidDegreeBoundedCoverage, Selected.requireCoverage(a, &shape, 0, 1, changed));
        }
        @memcpy(changed, selected.slots);
        changed[i].kind.lookup.entries[1] = 77;
        try std.testing.expectError(error.InvalidDegreeBoundedCoverage, Selected.requireCoverage(a, &shape, 0, 1, changed));
        break;
    }
}

fn frameDigest(layout: *const Selected.Layout, claims: []const Fused.Claim) ![32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixRoot(layout.digest);
    try Fused.recordClaims(&channel, @splat(3), @splat(7), 0, layout.slots, &.{}, claims, &.{});
    return channel.digestBytes();
}
test "degree-bounded physical claim framing binds each singleton before interaction" {
    const a = std.testing.allocator;
    var shape = shapeFor(.mul);
    var layout = try Selected.Layout.init(a, &shape, 0, 1);
    defer layout.deinit();
    const claims = try a.alloc(Fused.Claim, layout.slots.len);
    defer a.free(claims);
    for (claims, layout.slots) |*claim, slot| claim.* = .{ .row_count = slot.n_rows, .sum = Q.zero() };
    const expected = try frameDigest(&layout, claims);
    for (0..claims.len) |i| {
        const other = (i + 1) % claims.len;
        claims[i].sum = Q.one();
        claims[other].sum = Q.zero().sub(Q.one());
        try std.testing.expect(!std.meta.eql(expected, try frameDigest(&layout, claims)));
        claims[i].sum = Q.zero();
        claims[other].sum = Q.zero();
    }
    try std.testing.expectError(error.InvalidV5FullFusedClaims, frameDigest(&layout, claims[1..]));
    claims[0].row_count += 1;
    try std.testing.expectError(error.InvalidV5FullFusedClaims, frameDigest(&layout, claims));
}
