const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const opcode = @import("../runner/trace.zig");
const Ordinary = @import("block_execution_sidecar_batch_v2.zig");
const Access = @import("block_execution_access_bridge_v2.zig");
const External = @import("block_execution_external_trace_v2.zig");
const Bytes = @import("block_v5_memory_byte_demand_v1.zig");
const Caller = @import("block_v5_precompile_protocol_v1.zig");

test "block-v5 RW scope uses authentic opcode space and preserves legacy slot ordering" {
    const a = std.testing.allocator;
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 };
    for (0..opcode.N_FAMILIES) |family_index| {
        const family: opcode.OpcodeFamily = @enumFromInt(family_index);
        const Descriptor = struct { family: opcode.OpcodeFamily, n_columns: usize, log_size: u32 };
        const descriptors = [_]Descriptor{.{ .family = family, .n_columns = opcode.nColumnsForFamily(family), .log_size = 1 }};
        const statement = .{ .component_descs = &descriptors, .n_components = @as(usize, 1) };
        const all = try Ordinary.slotsFromStatement(a, &statement, frame);
        defer a.free(all);
        const rw = try Ordinary.slotsFromStatementForMode(a, &statement, frame, 1);
        defer a.free(rw);
        try Ordinary.requireRwSlots(rw, 1);
        var seen: usize = 0;
        var arbitrary: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        for (&arbitrary, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(11 + 7 * i), 13, 17, 19);
        const pairs = try Access.fromCommittedMain(Q, family, arbitrary[0..opcode.nColumnsForFamily(family)]);
        for (all) |slot| {
            const pair = pairs.items[slot.slot];
            if (pair.space.eql(Q.one()) or Access.hasConditionalSpace(family, slot.slot)) {
                try std.testing.expect(std.meta.eql(slot, rw[seen]));
                const projected = try Access.rwPairForMode(Q, family, slot.slot, pair, 1);
                try std.testing.expect(projected.space.eql(Q.one()));
                try std.testing.expect(projected.active.eql(if (Access.hasConditionalSpace(family, slot.slot)) pair.space else pair.active));
                seen += 1;
            } else try std.testing.expect(pair.space.eql(Q.zero()));
        }
        try std.testing.expectEqual(seen, rw.len);
        if (all.len != rw.len) try std.testing.expectError(error.MixedV5OpcodeMemoryScope, Ordinary.requireRwSlots(all, 1)) else try Ordinary.requireRwSlots(all, 1);
        try std.testing.expectError(error.InvalidV5RegisterCustodyMode, Ordinary.slotsFromStatementForMode(a, &statement, frame, 2));
    }
}

test "block-v5 RW conditional load store projection preserves native selectors at rows and OODS" {
    var columns: [opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
    // Authentic load/store geometry: source is memory only on loads and
    // destination only on stores. Both slots stay in the committed roster.
    for ([_]usize{ 38, 41 }) |selector| {
        @memset(&columns, Q.zero());
        columns[selector] = Q.one();
        const pairs = try Access.fromCommittedMain(Q, .load_store, columns[0..opcode.nColumnsForFamily(.load_store)]);
        var active: u64 = 0;
        for ([_]usize{ 1, 2 }) |slot| {
            const projected = try Access.rwPairForMode(Q, .load_store, slot, pairs.items[slot], 1);
            try std.testing.expect(projected.space.eql(Q.one()));
            try std.testing.expect(projected.active.eql(pairs.items[slot].space));
            active += @intFromBool(projected.active.eql(Q.one()));
            const unfiltered = try Access.rwPairForMode(Q, .load_store, slot, pairs.items[slot], 0);
            try std.testing.expect(std.meta.eql(unfiltered, pairs.items[slot]));
        }
        try std.testing.expectEqual(@as(u64, 1), active);
    }
    // No field-value branch: retain the same polynomial at an arbitrary
    // extension-field point, where neither selector is a Boolean value.
    for (&columns, 0..) |*value, index| value.* = Q.fromU32Unchecked(@intCast(index + 1), 13, 17, 19);
    const oods = try Access.fromCommittedMain(Q, .load_store, columns[0..opcode.nColumnsForFamily(.load_store)]);
    for ([_]usize{ 1, 2 }) |slot| {
        const projected = try Access.rwPairForMode(Q, .load_store, slot, oods.items[slot], 1);
        try std.testing.expect(projected.active.eql(oods.items[slot].space));
        try std.testing.expect(projected.source_address.eql(oods.items[slot].source_address));
        try std.testing.expect(projected.local_clock.eql(oods.items[slot].local_clock));
        try std.testing.expect(std.meta.eql(projected.before, oods.items[slot].before));
        try std.testing.expect(std.meta.eql(projected.after, oods.items[slot].after));
    }
}

test "block-v5 RW caller scope excludes pointer registers with exact byte demand" {
    const a = std.testing.allocator;
    const geometry = @import("../air/guest_precompile/ethereum_statement.zig");
    var shapes: geometry.SecpShapes = undefined;
    inline for (@typeInfo(geometry.SecpShapes).@"struct".fields) |field| @field(shapes, field.name) = .{ .log_size = 1, .n_rows = 1 };
    shapes.byte = .{ .log_size = 8, .n_rows = 256 };
    const statement = try @import("block_v5_precompile_witness_v1.zig").canonicalStatement(a, 1, 1, 2, shapes);
    const fixed = try Caller.columnLogs(a, &statement, .fixed);
    defer a.free(fixed);
    const main = try Caller.columnLogs(a, &statement, .main);
    defer a.free(main);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 4 };
    const all = try External.descriptorsFromStatement(a, &statement, fixed, main, frame);
    defer a.free(all);
    const rw = try External.descriptorsFromStatementForMode(a, &statement, fixed, main, frame, 1);
    defer a.free(rw);
    try std.testing.expectEqual(@as(usize, 120), all.len);
    try std.testing.expectEqual(@as(usize, 116), rw.len);
    const legacy = try Bytes.externalDemand(&statement, all);
    const selected = try Bytes.externalDemandForMode(&statement, rw, 1);
    try std.testing.expectEqual(@as(u64, 146), legacy.event_count);
    try std.testing.expectEqual(@as(u64, 140), selected.event_count);
    try std.testing.expectEqual(@as(u64, 14 * 140), selected.request_count);
    try std.testing.expectEqual(selected.request_count, selected.max_requests);
    try std.testing.expectError(error.MixedV5ExternalMemoryScope, Bytes.externalDemandForMode(&statement, all, 1));
    var seen: usize = 0;
    for (all) |slot| {
        const is_register = if (slot.kind == .sha) slot.slot < 2 else slot.slot == 0;
        if (!is_register) {
            try std.testing.expect(std.meta.eql(slot, rw[seen]));
            seen += 1;
        }
    }
    try std.testing.expectEqual(rw.len, seen);
    var changed = rw[0];
    changed.slot = 0;
    try std.testing.expectError(error.MixedV5ExternalMemoryScope, External.requireRwDescriptors(&.{changed}, 1));
    try std.testing.expectError(error.InvalidV5RegisterCustodyMode, External.expectedEventCountForMode(&statement, 2));
}
