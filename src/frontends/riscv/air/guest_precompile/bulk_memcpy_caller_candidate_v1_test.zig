const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");

const Sink = struct {
    count: usize = 0,
    nonzero: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: M31, degree: u8) void {
        self.count += 1;
        self.nonzero += @intFromBool(!value.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "bulk memcpy caller canonical zero padding satisfies every direct constraint" {
    const encoded = caller.Row.padding().encode();
    var sink = Sink{};
    try caller.evaluateDirect(M31, &encoded, &sink);
    try std.testing.expectEqual(@as(usize, 176), sink.count);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    try std.testing.expectEqual(caller.maximum_constraint_degree, sink.maximum_degree);
}

test "bulk memcpy caller candidate binds fixed registers and exact first-word tuple" {
    const record = caller.Record{
        .execution_clock = 73,
        .pc = 0x0040_0000,
        .destination_previous_clock = 3,
        .source_previous_clock = 7,
        .length_previous_clock = 11,
        .destination = 0x0002_0001,
        .source = 0x0003_0001,
        .length = 32,
        .call_index = 19,
    };
    const row = try caller.materialize(record);
    try std.testing.expect(row.destination_before_source);
    try std.testing.expectEqualDeep(record.call().tuple(), try row.callTuple());
    const encoded = row.encode();
    var sink = Sink{};
    try caller.evaluateDirect(M31, &encoded, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    try std.testing.expect(sink.count != 0);
    try std.testing.expectEqual(caller.maximum_constraint_degree, sink.maximum_degree);

    const events = try row.relationEvents();
    try std.testing.expectEqualDeep(abi.programTuple(record.pc), events.program);
    try std.testing.expectEqualDeep(
        [_]u32{ record.pc, record.execution_clock },
        events.state_before,
    );
    try std.testing.expectEqualDeep(
        [_]u32{ record.pc + 4, record.execution_clock + 1 },
        events.state_after,
    );
    try std.testing.expectEqual(abi.destination_register, events.registers[0].before.register);
    try std.testing.expectEqual(abi.source_register, events.registers[1].before.register);
    try std.testing.expectEqual(abi.length_register, events.registers[2].before.register);
    try std.testing.expectEqual(
        access_clock.encode(record.execution_clock, .first),
        events.registers[0].after.clock,
    );
    try std.testing.expectEqualDeep(record.call().tuple(), events.call);
}

test "bulk memcpy caller candidate rejects invalid clock span and overlap authority" {
    const canonical = caller.Record{
        .execution_clock = 10,
        .pc = 0x400,
        .destination_previous_clock = 1,
        .source_previous_clock = 2,
        .length_previous_clock = 3,
        .destination = 0x2000,
        .source = 0x3000,
        .length = 32,
        .call_index = 0,
    };
    try canonical.validate();
    var changed = canonical;
    changed.destination_previous_clock = access_clock.encode(10, .first);
    try std.testing.expectError(error.InvalidCallerRecord, changed.validate());
    changed = canonical;
    changed.destination = 0x3010;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.source = 0x1001;
    changed.destination = 0x1021;
    try std.testing.expectError(error.InvalidCall, changed.validate());
    changed = canonical;
    changed.source = words.data_address_limit - 16;
    try std.testing.expectError(error.InvalidCall, changed.validate());
}

test "bulk memcpy caller field constraints reject resealed span and range mutations" {
    const record = caller.Record{
        .execution_clock = 101,
        .pc = 0x800,
        .destination_previous_clock = 9,
        .source_previous_clock = 10,
        .length_previous_clock = 11,
        .destination = 0x0005_0002,
        .source = 0x0004_0002,
        .length = 66,
        .call_index = 1,
    };
    var row = try caller.materialize(record);
    try std.testing.expect(!row.destination_before_source);
    var encoded = row.encode();
    var sink = Sink{};
    try caller.evaluateDirect(M31, &encoded, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);

    row.values[1] += 4;
    encoded = row.encode();
    sink = .{};
    try caller.evaluateDirect(M31, &encoded, &sink);
    try std.testing.expect(sink.nonzero != 0);

    row = try caller.materialize(record);
    row.high_bits[0][0] = !row.high_bits[0][0];
    encoded = row.encode();
    sink = .{};
    try caller.evaluateDirect(M31, &encoded, &sink);
    try std.testing.expect(sink.nonzero != 0);
}
