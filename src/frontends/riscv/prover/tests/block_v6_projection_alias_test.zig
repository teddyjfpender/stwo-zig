const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Trace = @import("../../runner/trace.zig");
const Entries = @import("../../air/lookups/opcode_entries.zig");
const Interaction = @import("../../air/lookups/opcode_interaction.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Alias = @import("../block_v6_projection_alias_v1.zig");

test "block-v6 projection aliases preserve exact rational functions across every opcode family" {
    const a = std.testing.allocator;
    const U = @import("../../recursion/air/universal_challenges.zig");
    var draws: [U.DRAW_COUNT]Q = undefined;
    for (&draws, 0..) |*draw, i| draw.* = Q.fromU32Unchecked(@intCast(100 + i), @intCast(50 + i), 3, 7);
    const universal = U.UniversalRelations.fromDraws(&draws);
    const shared = try @import("../../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    var accepted: usize = 0;
    var rejected: usize = 0;
    for (0..Trace.N_FAMILIES) |ordinal| {
        const family: Trace.OpcodeFamily = @enumFromInt(ordinal);
        var plan = try Interaction.Plan.init(a, family);
        defer plan.deinit();
        for (0..@intFromEnum(Source.Partition.register_memory_access) + 1) |partition_ordinal| {
            const partition: Source.Partition = @enumFromInt(partition_ordinal);
            for (0..Entries.batchCount(family)) |batch| {
                const first = batch * plan.program.batch_size;
                const count = @min(plan.program.batch_size, plan.program.entries.len - first);
                if (count > 2) continue;
                for ([_]u32{ 0, 1 }) |mode| {
                    var slot = Source.Slot{
                        .kind = .{ .lookup = .{ .source = .{ .opcode = family }, .partition = partition, .entries = .{ @intCast(first), @intCast(if (count == 2) first + 1 else 0) }, .entry_count = @intCast(count), .degree = 4, .log_size = 4, .n_rows = 3, .main_offset = 0, .width = Trace.nColumnsForFamily(family), .register_custody_mode = mode } },
                        .degree = 4,
                        .log_size = 4,
                        .n_rows = 3,
                        .main_offset = 0,
                        .width = Trace.nColumnsForFamily(family),
                        .register_custody_mode = mode,
                    };
                    const alias = try Alias.batchFor(plan, slot);
                    if (alias == null) {
                        rejected += 1;
                        continue;
                    }
                    accepted += 1;
                    try std.testing.expectEqual(batch, alias.?);
                    // Arbitrary extension-field points, including non-Boolean
                    // load/store selectors. Equality must be polynomial, not
                    // contingent on a convenient zero witness sample.
                    for (0..3) |seed| {
                        var columns: [Trace.MAX_FAMILY_COLUMNS]Q = undefined;
                        for (&columns, 0..) |*column, i| column.* = Q.fromU32Unchecked(@intCast(17 * seed + i + 1), @intCast(i + 2), @intCast(seed + 3), 9);
                        const main = columns[0..slot.width];
                        const list = try Entries.fromMain(family, main);
                        const native = try list.pair(batch, &shared.native);
                        const projection = try Source.fromCommittedMain(slot, main, &universal);
                        const numerator = native.n1.mul(native.d2).add(native.n2.mul(native.d1));
                        try std.testing.expect(numerator.mul(projection.denominator()).eql(projection.numerator().mul(native.d1.mul(native.d2))));
                    }
                    if (count == 2) {
                        slot.kind.lookup.entry_count = 1;
                        try std.testing.expectEqual(@as(?usize, null), try Alias.batchFor(plan, slot));
                        slot.kind.lookup.entry_count = 2;
                        slot.kind.lookup.entries[1] = slot.kind.lookup.entries[0];
                        try std.testing.expectEqual(@as(?usize, null), try Alias.batchFor(plan, slot));
                    }
                }
            }
        }
        // A fetch can only alias a whole singleton physical batch.
        const program = Source.Slot{ .kind = .{ .program = family }, .degree = 3, .log_size = 4, .n_rows = 3, .main_offset = 0, .width = Trace.nColumnsForFamily(family), .register_custody_mode = 0 };
        if (try Alias.batchFor(plan, program)) |batch| {
            try std.testing.expectEqual(@as(usize, 1), @min(plan.program.batch_size, plan.program.entries.len - batch * plan.program.batch_size));
            try std.testing.expectEqual(.program_access, plan.domains[batch * plan.program.batch_size]);
        }
    }
    try std.testing.expect(accepted > 0 and rejected > accepted);
}
