const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data_v2 = @import("public_data_v2.zig");
const public_logup_v2 = @import("public_logup_v2.zig");
const relation_challenges = @import("relation_challenges.zig");
const runner_result = @import("../runner/result.zig");
const support = @import("public_data_v2_test_support.zig");

test "public LogUp V2 compensation is the inverse of exact boundary transitions" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const relations = relation_challenges.Relations.dummy();

    const compensation = try public_logup_v2.relationSums(&data, &relations);
    const transition = try public_logup_v2.transitionSums(&data, &relations);
    try std.testing.expect(
        compensation.registers_state.eql(transition.registers_state.neg()),
    );
    try std.testing.expect(
        compensation.memory_access.eql(transition.memory_access.neg()),
    );
    try std.testing.expect(!compensation.program_access.isZero());
    try std.testing.expect(!compensation.merkle.isZero());
    try std.testing.expect(compensation.total().eql(try public_logup_v2.sum(
        &data,
        &relations,
    )));
}

test "public LogUp V2 adjacent shared CPU register and sparse memory tuples cancel" {
    var fixture = try support.Fixture.init();
    const left_source = fixture.leftSource();
    const right_source = fixture.rightSource();
    const left_words = try support.encode(std.testing.allocator, &left_source);
    defer std.testing.allocator.free(left_words);
    const right_words = try support.encode(std.testing.allocator, &right_source);
    defer std.testing.allocator.free(right_words);
    const left = try public_data_v2.PublicDataV2.authenticate(left_words);
    const right = try public_data_v2.PublicDataV2.authenticate(right_words);
    _ = try public_data_v2.PublicDataV2.authenticateAdjacent(&left, &right);

    var left_cursor = try left.eventCursor();
    var right_cursor = try right.eventCursor();
    var left_exit: [35]public_data_v2.BoundaryEvent = undefined;
    var right_entry: [35]public_data_v2.BoundaryEvent = undefined;
    var left_count: usize = 0;
    var right_count: usize = 0;
    while (left_cursor.next()) |event| {
        if (direction(event) == .produce) {
            left_exit[left_count] = event;
            left_count += 1;
        }
    }
    while (right_cursor.next()) |event| {
        if (direction(event) == .consume) {
            right_entry[right_count] = event;
            right_count += 1;
        }
    }
    // The 34 explicitly retained shared tuples cancel exactly. Address 0x2004
    // is first touched by the right segment, so the zero-normalized left exit
    // omits it while the right transition must consume its implicit sparse
    // default `(clock=0,value=0)` before writing it.
    try std.testing.expectEqual(@as(usize, 34), left_count);
    try std.testing.expectEqual(@as(usize, 35), right_count);
    for (left_exit[0..left_count], right_entry[0..left_count]) |lhs, rhs| {
        try expectOppositeDirectionsSameTuple(lhs, rhs);
    }
    switch (right_entry[right_count - 1]) {
        .memory_access => |memory| {
            try std.testing.expectEqual(public_data_v2.Direction.consume, memory.direction);
            try std.testing.expectEqual(@as(u1, 1), memory.address_space);
            try std.testing.expectEqual(@as(u32, 0x2004), memory.address);
            try std.testing.expectEqual(@as(u32, 0), memory.predecessor_clock);
            try std.testing.expectEqual(@as(u32, 0), memory.value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "public LogUp V2 uses a non-first memory predecessor instead of clock zero" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const baseline_words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(baseline_words);
    const baseline = try public_data_v2.PublicDataV2.authenticate(baseline_words);

    const changed_entry_clocks = [_]runner_result.MemoryAccessClock{
        .{ .addr = 0x2000, .clock = 3 },
        .{ .addr = 0x2004, .clock = 2 },
    };
    var changed_source = fixture.rightSource();
    changed_source.entry_memory_clocks = &changed_entry_clocks;
    const changed_words = try support.encode(std.testing.allocator, &changed_source);
    defer std.testing.allocator.free(changed_words);
    const changed = try public_data_v2.PublicDataV2.authenticate(changed_words);

    const relations = relation_challenges.Relations.dummy();
    const baseline_sum = try public_logup_v2.relationSums(&baseline, &relations);
    const changed_sum = try public_logup_v2.relationSums(&changed, &relations);
    try std.testing.expect(
        !baseline_sum.memory_access.eql(changed_sum.memory_access),
    );

    var cursor = try changed.eventCursor();
    var found = false;
    while (cursor.next()) |event| switch (event) {
        .memory_access => |memory| {
            if (memory.direction == .consume and
                memory.address_space == 1 and
                memory.address == 0x2004)
            {
                found = true;
                try std.testing.expectEqual(@as(u32, 2), memory.predecessor_clock);
                try std.testing.expectEqual(@as(u32, 0), memory.value);
            }
        },
        else => {},
    };
    try std.testing.expect(found);
}

test "public LogUp V2 output is fail atomic on zero denominator and unsupported root" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);

    var relations = relation_challenges.Relations.dummy();
    const alpha = QM31.one();
    const zero_denominator_z = QM31.fromBase(M31.fromU64(0x1008))
        .add(alpha.mulM31(M31.fromU64(3)));
    relations.registers_state = relation_challenges.RelationElements(2).init(
        zero_denominator_z,
        alpha,
    );
    const sentinel = sentinelSums();
    var destination = sentinel;
    try std.testing.expectError(
        error.ZeroDenominator,
        public_logup_v2.writeRelationSums(&data, &relations, &destination),
    );
    try expectSumsEqual(sentinel, destination);

    var nonscalar_source = fixture.rightSource();
    nonscalar_source.base_statement.job.complete.program[1] = 1;
    const nonscalar_words = try support.encode(
        std.testing.allocator,
        &nonscalar_source,
    );
    defer std.testing.allocator.free(nonscalar_words);
    const nonscalar = try public_data_v2.PublicDataV2.authenticate(nonscalar_words);
    destination = sentinel;
    try std.testing.expectError(
        error.NonScalarProgramRoot,
        public_logup_v2.writeRelationSums(
            &nonscalar,
            &relation_challenges.Relations.dummy(),
            &destination,
        ),
    );
    try expectSumsEqual(sentinel, destination);
}

fn direction(event: public_data_v2.BoundaryEvent) public_data_v2.Direction {
    return switch (event) {
        .registers_state => |value| value.direction,
        .memory_access => |value| value.direction,
    };
}

fn expectOppositeDirectionsSameTuple(
    left: public_data_v2.BoundaryEvent,
    right: public_data_v2.BoundaryEvent,
) !void {
    switch (left) {
        .registers_state => |lhs| switch (right) {
            .registers_state => |rhs| {
                try std.testing.expectEqual(public_data_v2.Direction.produce, lhs.direction);
                try std.testing.expectEqual(public_data_v2.Direction.consume, rhs.direction);
                try std.testing.expectEqual(lhs.pc, rhs.pc);
                try std.testing.expectEqual(lhs.clock, rhs.clock);
            },
            else => return error.TestExpectedEqual,
        },
        .memory_access => |lhs| switch (right) {
            .memory_access => |rhs| {
                try std.testing.expectEqual(public_data_v2.Direction.produce, lhs.direction);
                try std.testing.expectEqual(public_data_v2.Direction.consume, rhs.direction);
                try std.testing.expectEqual(lhs.address_space, rhs.address_space);
                try std.testing.expectEqual(lhs.address, rhs.address);
                try std.testing.expectEqual(lhs.predecessor_clock, rhs.predecessor_clock);
                try std.testing.expectEqual(lhs.value, rhs.value);
            },
            else => return error.TestExpectedEqual,
        },
    }
}

fn sentinelSums() public_logup_v2.Sums {
    return .{
        .registers_state = QM31.fromU32Unchecked(1, 2, 3, 4),
        .memory_access = QM31.fromU32Unchecked(5, 6, 7, 8),
        .program_access = QM31.fromU32Unchecked(9, 10, 11, 12),
        .merkle = QM31.fromU32Unchecked(13, 14, 15, 16),
    };
}

fn expectSumsEqual(
    expected: public_logup_v2.Sums,
    actual: public_logup_v2.Sums,
) !void {
    try std.testing.expect(expected.registers_state.eql(actual.registers_state));
    try std.testing.expect(expected.memory_access.eql(actual.memory_access));
    try std.testing.expect(expected.program_access.eql(actual.program_access));
    try std.testing.expect(expected.merkle.eql(actual.merkle));
}
