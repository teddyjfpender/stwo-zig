const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate = @import("bulk_memcpy_word_candidate_v1.zig");
const component = @import("bulk_memcpy_component_v1.zig");
const relations_mod = @import("bulk_memcpy_relations_v1.zig");

const Sink = struct {
    constraint_count: usize = 0,
    nonzero_count: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: M31, degree: u8) void {
        self.constraint_count += 1;
        self.maximum_degree = @max(self.maximum_degree, degree);
        self.nonzero_count += @intFromBool(!value.isZero());
    }
};

test "bulk memcpy word candidate materializes exact same-mod-four call authority" {
    const call = candidate.Call{
        .execution_clock = 91,
        .call_index = 7,
        .pc = 0x0012_3400,
        .source = 0x0002_0001,
        .destination = 0x0003_0001,
        .length = 32,
    };
    try call.validate();
    try std.testing.expectEqual(@as(u32, 9), call.expectedWordCount());
    try std.testing.expectEqual(@as(u2, 1), call.startOffset());
    try std.testing.expectEqual(@as(u3, 1), call.endOffset());

    var rows: [9]candidate.Row = undefined;
    var copied_bytes: usize = 0;
    for (&rows, 0..) |*row, index| {
        const value: u8 = @intCast(index + 1);
        row.* = try candidate.materializeRow(call, @intCast(index), .{
            .source_previous_clock = @intCast(10 + index),
            .destination_previous_clock = @intCast(20 + index),
            .source_bytes = .{ value, value + 1, value + 2, value + 3 },
            .destination_before = .{ 201, 202, 203, 204 },
        });
        for (row.byte_mask) |selected| copied_bytes += @intFromBool(selected);
    }
    try std.testing.expectEqual(@as(usize, 32), copied_bytes);
    try std.testing.expectEqualDeep(call.tuple(), try rows[0].firstCallTuple());
    try std.testing.expect(rows[0].is_first);
    try std.testing.expect(!rows[0].is_last);
    try std.testing.expect(!rows[8].is_first);
    try std.testing.expect(rows[8].is_last);
    try std.testing.expectEqualDeep(
        [_]bool{ false, true, true, true },
        rows[0].byte_mask,
    );
    try std.testing.expectEqualDeep(
        [_]bool{ true, false, false, false },
        rows[8].byte_mask,
    );

    const padding = candidate.Row.padding().encode();
    for (rows, 0..) |row, index| {
        const current = row.encode();
        const next = if (index + 1 < rows.len) rows[index + 1].encode() else padding;
        var sink = Sink{};
        try candidate.evaluateDirect(M31, &current, &next, &sink);
        try std.testing.expectEqual(@as(usize, 0), sink.nonzero_count);
        try std.testing.expect(sink.constraint_count != 0);
        try std.testing.expectEqual(candidate.maximum_constraint_degree, sink.maximum_degree);
    }
}

test "bulk memcpy word candidate rejects overlap short calls and alignment mismatch" {
    const canonical = candidate.Call{
        .execution_clock = 1,
        .call_index = 0,
        .pc = 4,
        .source = 0x1000,
        .destination = 0x2000,
        .length = 32,
    };
    try canonical.validate();
    var changed = canonical;
    changed.length = 31;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.source += 1;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.destination = 0x1010;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.source = 0x1001;
    changed.destination = 0x1021;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.execution_clock = 0;
    try std.testing.expectError(error.InvalidCall, changed.validate());
}

test "bulk memcpy word candidate field constraints detect byte mask and recurrence mutations" {
    const call = candidate.Call{
        .execution_clock = 27,
        .call_index = 3,
        .pc = 0x400,
        .source = 0x1001,
        .destination = 0x2001,
        .length = 32,
    };
    var first = try candidate.materializeRow(call, 0, .{
        .source_previous_clock = 1,
        .destination_previous_clock = 2,
        .source_bytes = .{ 11, 12, 13, 14 },
        .destination_before = .{ 21, 22, 23, 24 },
    });
    var second = try candidate.materializeRow(call, 1, .{
        .source_previous_clock = 3,
        .destination_previous_clock = 4,
        .source_bytes = .{ 31, 32, 33, 34 },
        .destination_before = .{ 41, 42, 43, 44 },
    });
    var current = first.encode();
    var next = second.encode();
    var sink = Sink{};
    try candidate.evaluateDirect(M31, &current, &next, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero_count);

    first.destination_after[1] +%= 1;
    current = first.encode();
    sink = .{};
    try candidate.evaluateDirect(M31, &current, &next, &sink);
    try std.testing.expect(sink.nonzero_count != 0);

    first = try candidate.materializeRow(call, 0, .{
        .source_previous_clock = 1,
        .destination_previous_clock = 2,
        .source_bytes = .{ 11, 12, 13, 14 },
        .destination_before = .{ 21, 22, 23, 24 },
    });
    second.source_word_index += 2;
    current = first.encode();
    next = second.encode();
    sink = .{};
    try candidate.evaluateDirect(M31, &current, &next, &sink);
    try std.testing.expect(sink.nonzero_count != 0);
}

test "bulk memcpy caller tuple rejects a fully resealed false first-row offset" {
    const call = candidate.Call{
        .execution_clock = 44,
        .call_index = 8,
        .pc = 0x800,
        .source = 0x1001,
        .destination = 0x2001,
        .length = 32,
    };
    var first = try candidate.materializeRow(call, 0, .{
        .source_previous_clock = 5,
        .destination_previous_clock = 6,
        .source_bytes = .{ 1, 2, 3, 4 },
        .destination_before = .{ 5, 6, 7, 8 },
    });
    first.start_selectors = .{ true, false, false, false };
    first.byte_mask = .{ true, true, true, true };
    first.destination_after = first.source_bytes;
    const next = (try candidate.materializeRow(call, 1, .{
        .source_previous_clock = 7,
        .destination_previous_clock = 8,
        .source_bytes = .{ 9, 10, 11, 12 },
        .destination_before = .{ 13, 14, 15, 16 },
    })).encode();
    var sink = Sink{};
    const current = first.encode();
    try candidate.evaluateDirect(M31, &current, &next, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero_count);
    try std.testing.expect(!std.meta.eql(call.tuple(), try first.firstCallTuple()));
}

test "bulk memcpy memory events retain source and destination clock chains" {
    const call = candidate.Call{
        .execution_clock = 9,
        .call_index = 0,
        .pc = 0x40,
        .source = 0x1000,
        .destination = 0x2000,
        .length = 32,
    };
    const row = try candidate.materializeRow(call, 0, .{
        .source_previous_clock = 2,
        .destination_previous_clock = 3,
        .source_bytes = .{ 1, 2, 3, 4 },
        .destination_before = .{ 5, 6, 7, 8 },
    });
    const events = try row.memoryEvents();
    const call_tuple = try row.firstCallTuple();
    try std.testing.expectEqual(call.source / 4, call_tuple.source_word_index);
    try std.testing.expectEqual(
        call.destination / 4,
        call_tuple.destination_word_index,
    );
    try std.testing.expectEqualDeep(
        candidate.MemoryTuple{
            .address = call.source,
            .clock = 2,
            .bytes = .{ 1, 2, 3, 4 },
        },
        events[0].request,
    );
    try std.testing.expectEqualDeep(
        candidate.MemoryTuple{
            .address = call.destination,
            .clock = @import("../../access_clock.zig").encode(9, .second),
            .bytes = .{ 1, 2, 3, 4 },
        },
        events[3].emit,
    );

    const relations = relations_mod.Relations.dummy();
    const main = row.encode();
    const air_events = component.wordEvents(M31, &main, &relations);
    try std.testing.expect(air_events[0].denominator.eql(memoryDenominator(
        events[0].request,
        &relations,
    )));
    try std.testing.expect(air_events[1].denominator.eql(memoryDenominator(
        events[1].emit,
        &relations,
    )));
    try std.testing.expect(air_events[2].denominator.eql(memoryDenominator(
        events[2].request,
        &relations,
    )));
    try std.testing.expect(air_events[3].denominator.eql(memoryDenominator(
        events[3].emit,
        &relations,
    )));

    var changed = row;
    changed.source_word_index += 1;
    const changed_events = try changed.memoryEvents();
    try std.testing.expectEqual(call.source + 4, changed_events[0].request.address);
    const changed_main = changed.encode();
    const changed_air_events = component.wordEvents(M31, &changed_main, &relations);
    try std.testing.expect(changed_air_events[0].denominator.eql(memoryDenominator(
        changed_events[0].request,
        &relations,
    )));

    changed.source_word_index = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidRow, changed.memoryEvents());
    changed = row;
    changed.destination_word_index = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidRow, changed.memoryEvents());
}

fn memoryDenominator(
    event: candidate.MemoryTuple,
    relations: *const relations_mod.Relations,
) @import("stwo_core").fields.qm31.QM31 {
    return relations_mod.combine(
        M31,
        relations.base.memory_access,
        [7]M31{
            M31.fromCanonical(event.address_space),
            M31.fromCanonical(event.address),
            M31.fromCanonical(event.clock),
            M31.fromCanonical(event.bytes[0]),
            M31.fromCanonical(event.bytes[1]),
            M31.fromCanonical(event.bytes[2]),
            M31.fromCanonical(event.bytes[3]),
        },
    );
}
