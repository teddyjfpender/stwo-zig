//! Symbolic ordinal coverage plus polynomial-value parity at arbitrary QM31 points.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const LayoutModule = @import("../block_v6_relation_layout_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
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

test "block-v6 partitioned symbolic complete coverage every family and local zero" {
    const a = std.testing.allocator;
    var channel = core.proof_suites.Blake3.Channel{};
    const U = @import("../../recursion/air/universal_challenges.zig");
    const universal = try U.UniversalRelations.draw(a, &channel);
    const shared = try @import("../../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    for (0..Opcode.N_FAMILIES) |ordinal| {
        const family: Opcode.OpcodeFamily = @enumFromInt(ordinal);
        for ([_]bool{ false, true }) |local_zero| {
            var shape = shapeFor(family);
            if (local_zero) {
                shape.x0_local_custody_version = @import("../../air/x0_local_custody_v1.zig").VERSION;
                shape.component_descs[0].n_columns = @intCast(try @import("../../air/x0_native_envelope_v1.zig").mainColumnCount(family));
            }
            for ([_]u32{ 0, 1 }) |mode| {
                if (local_zero and mode == 0) continue;
                var layout = try LayoutModule.Layout.init(a, &shape, 0, mode);
                defer layout.deinit();
                try LayoutModule.requireCoverage(a, &shape, 0, mode, layout.slots);
                try std.testing.expectError(error.IncompletePartitionedRelation, LayoutModule.requireCoverage(a, &shape, 0, mode, layout.slots[0 .. layout.slots.len - 1]));
                const copied = try a.dupe(Source.Slot, layout.slots);
                defer a.free(copied);
                copied[copied.len - 1] = copied[0];
                if (LayoutModule.requireCoverage(a, &shape, 0, mode, copied)) |_| return error.AcceptedDuplicateRelation else |_| {}
                for (layout.slots, 0..) |slot, slot_index| {
                    if (slot.kind != .lookup or slot.kind.lookup.partition != .ordinary_memory_access) continue;
                    inline for (.{ "main_offset", "n_rows", "width", "degree" }) |field| {
                        @memcpy(copied, layout.slots);
                        @field(copied[slot_index].kind.lookup, field) += 1;
                        try std.testing.expectError(error.InvalidPartitionedRelationGeometry, LayoutModule.requireCoverage(a, &shape, 0, mode, copied));
                    }
                    @memcpy(copied, layout.slots);
                    copied[slot_index].register_custody_mode = 1 - mode;
                    if (LayoutModule.requireCoverage(a, &shape, 0, mode, copied)) |_| return error.AcceptedChangedPartitionWeight else |_| {}
                    break;
                }
                for (0..3) |seed| {
                    var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
                    for (&row, 0..) |*cell, i| cell.* = Q.fromU32Unchecked(@intCast(1 + i + seed * 71), @intCast(i + 3), @intCast(seed + 3), 11);
                    const width = shape.component_descs[0].n_columns;
                    const original = try @import("../../air/lookups/opcode_entries.zig").Entries(Q).fromMain(family, row[0..width]);
                    var expected = Q.zero();
                    for (0..original.batchCount()) |batch| {
                        const p = try original.pair(batch, &shared.native);
                        expected = expected.add(p.n1.mul(try p.d1.inv())).add(p.n2.mul(try p.d2.inv()));
                    }
                    var got = Q.zero();
                    for (layout.slots) |slot| {
                        if (slot.main_offset != 0) continue; // separate clock geometry
                        const pair = try Source.fromCommittedMain(slot, row[0..slot.width], &universal);
                        got = got.add(pair.numerator().mul(try pair.denominator().inv()));
                    }
                    try std.testing.expectEqualDeep(expected, got);
                    const Clock = @import("../../air/clock_update_interaction.zig");
                    const clock_entries = Clock.orderedEntriesGeneric(Q, try Clock.RowFor(Q).fromMain(row[0..Clock.N_MAIN_COLUMNS]));
                    var clock_expected = Q.zero();
                    for (0..clock_entries.batchCount()) |batch| {
                        const pair = try clock_entries.pair(batch, &shared.native);
                        clock_expected = clock_expected.add(pair.n1.mul(try pair.d1.inv())).add(pair.n2.mul(try pair.d2.inv()));
                    }
                    var clock_got = Q.zero();
                    for (layout.slots) |slot| {
                        if (slot.kind != .lookup or slot.kind.lookup.source != .clock) continue;
                        const pair = try Source.fromCommittedMain(slot, row[0..slot.width], &universal);
                        clock_got = clock_got.add(pair.numerator().mul(try pair.denominator().inv()));
                    }
                    try std.testing.expectEqualDeep(clock_expected, clock_got);
                }
            }
        }
    }
}
