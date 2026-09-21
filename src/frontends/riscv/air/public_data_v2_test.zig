const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const public_data_v1 = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");
const support = @import("public_data_v2_test_support.zig");

test "public data V2 authenticates canonical metadata and mixes one distinct frame" {
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);

    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const view = try segment_v2.authenticateCanonicalWire(words);
    const reused = try public_data_v2.PublicDataV2.authenticateReusingRoots(
        words,
        .{
            .entry = .{
                .id = view.statement.entry_snapshot_id,
                .count = view.statement.entry_snapshot_count,
                .root = view.statement.entry_continuation_root,
            },
            .exit = .{
                .id = view.statement.exit_snapshot_id,
                .count = view.statement.exit_snapshot_count,
                .root = view.statement.exit_continuation_root,
            },
        },
    );
    const metadata = try data.metadata();
    try reused.validate();
    try std.testing.expectEqual(metadata, try reused.metadata());
    try std.testing.expectEqual(@as(u32, 0), metadata.segment_index);
    try std.testing.expectEqual(@as(u32, 2), metadata.segment_count);
    try std.testing.expectEqual(@as(u32, 0), metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 2), metadata.global_cycle_end);
    try std.testing.expect(metadata.is_first);
    try std.testing.expect(!metadata.is_final);
    try std.testing.expect(metadata.public_input != null);
    try std.testing.expect(metadata.public_output == null);
    try std.testing.expect(metadata.completion == null);
    try std.testing.expectEqual(@as(u32, 0x1000), metadata.entry_cpu.pc);
    try std.testing.expectEqual(@as(u32, 0x1008), metadata.exit_cpu.pc);
    try std.testing.expectEqual(@as(u32, 2), metadata.exit_cpu.predecessor_clocks[1]);
    try std.testing.expect(std.meta.eql(metadata.wire_id, data.wireId()));

    var channel = RecordingChannel{};
    try data.mixInto(&channel);
    try std.testing.expectEqual(@as(usize, 2), channel.u32_calls);
    try std.testing.expectEqual(@as(usize, 1), channel.canonical_calls);
    try std.testing.expectEqual(words.len, channel.canonical_words);
    try std.testing.expectEqualSlices(u32, &.{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
        @as(u32, @intCast(words.len)),
    }, channel.u32_words[0..4]);
    try std.testing.expectEqualSlices(u32, &metadata.wire_id, channel.u32_words[4..12]);
    try std.testing.expect(
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN !=
            public_data_v1.STATEMENT_TRANSCRIPT_DOMAIN,
    );
}

test "public data V2 emits exact non-first predecessor boundaries including sparse zero" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);

    const counts = try data.eventCounts();
    try std.testing.expectEqual(@as(usize, 2), counts.registers_state);
    try std.testing.expectEqual(@as(usize, 64), counts.register_memory);
    try std.testing.expectEqual(@as(usize, 2), counts.memory_address_count);
    try std.testing.expectEqual(@as(usize, 4), counts.rw_memory);
    try std.testing.expectEqual(@as(usize, 70), counts.total);

    var events: [70]public_data_v2.BoundaryEvent = undefined;
    _ = try data.writeBoundaryEvents(&events);
    try expectState(events[0], .consume, 0x1008, 3);
    try expectState(events[1], .produce, 0x1010, 5);
    try expectMemory(events[4], .consume, 0, 1, 2, 1);
    try expectMemory(events[5], .produce, 0, 1, 5, 2);
    try expectMemory(events[66], .consume, 1, 0x2000, 3, 12);
    try expectMemory(events[67], .produce, 1, 0x2000, 7, 13);
    // Address 0x2004 is absent from the entry sparse value and clock maps.
    // The four-way union must still emit its exact zero-default predecessor.
    try expectMemory(events[68], .consume, 1, 0x2004, 0, 0);
    try expectMemory(events[69], .produce, 1, 0x2004, 6, 9);
}

test "public data V2 event output and transcript are fail atomic" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);

    const sentinel = public_data_v2.BoundaryEvent{ .registers_state = .{
        .direction = .consume,
        .pc = 0xdead_beec,
        .clock = 0x1234,
    } };
    var too_short = [_]public_data_v2.BoundaryEvent{sentinel} ** 69;
    try std.testing.expectError(
        error.OutputLengthMismatch,
        data.writeBoundaryEvents(&too_short),
    );
    for (too_short) |event| try std.testing.expect(std.meta.eql(sentinel, event));

    const original = try std.testing.allocator.dupe(M31, words);
    defer std.testing.allocator.free(original);
    var alternate_source = fixture.rightSource();
    alternate_source.session_id = support.id("alternate-session");
    const alternate = try support.encode(std.testing.allocator, &alternate_source);
    defer std.testing.allocator.free(alternate);
    try std.testing.expectEqual(words.len, alternate.len);
    @memcpy(words, alternate);
    var channel = RecordingChannel{};
    try std.testing.expectError(error.SourceMutation, data.mixInto(&channel));
    try std.testing.expectEqual(@as(usize, 0), channel.u32_calls);
    try std.testing.expectEqual(@as(usize, 0), channel.canonical_calls);
    @memcpy(words, original);
}

test "public data V2 rejects clock address session adjacency and completion mutations" {
    var fixture = try support.Fixture.init();
    const left_source = fixture.leftSource();
    const right_source = fixture.rightSource();
    const left_words = try support.encode(std.testing.allocator, &left_source);
    defer std.testing.allocator.free(left_words);
    const right_words = try support.encode(std.testing.allocator, &right_source);
    defer std.testing.allocator.free(right_words);
    const left = try public_data_v2.PublicDataV2.authenticate(left_words);
    const right = try public_data_v2.PublicDataV2.authenticate(right_words);
    const receipt = try public_data_v2.PublicDataV2.authenticateAdjacent(&left, &right);
    try std.testing.expect(std.meta.eql(receipt.session_id, support.id("session")));

    var bad_clock = try std.testing.allocator.dupe(M31, left_words);
    defer std.testing.allocator.free(bad_clock);
    support.writeU32(
        bad_clock[segment_v2.fixed_layout.entry_register_clocks + 2 ..][0..2],
        5,
    );
    try std.testing.expectError(
        error.BoundaryClockOutOfRange,
        public_data_v2.PublicDataV2.authenticate(bad_clock),
    );

    const left_view = try segment_v2.authenticateCanonicalWire(left_words);
    var bad_address = try std.testing.allocator.dupe(M31, left_words);
    defer std.testing.allocator.free(bad_address);
    support.writeU32(
        bad_address[left_view.entry_snapshot.payload_start..][0..2],
        0x2001,
    );
    try std.testing.expectError(
        error.InvalidMemoryAddress,
        public_data_v2.PublicDataV2.authenticate(bad_address),
    );

    var cross_source = fixture.rightSource();
    cross_source.session_id = support.id("cross-session");
    const cross_words = try support.encode(std.testing.allocator, &cross_source);
    defer std.testing.allocator.free(cross_words);
    const cross = try public_data_v2.PublicDataV2.authenticate(cross_words);
    try std.testing.expectError(
        error.CrossSession,
        public_data_v2.PublicDataV2.authenticateAdjacent(&left, &cross),
    );

    var wrong_predecessor_source = fixture.rightSource();
    wrong_predecessor_source.entry_register_clocks[1] = 1;
    const wrong_predecessor_words = try support.encode(
        std.testing.allocator,
        &wrong_predecessor_source,
    );
    defer std.testing.allocator.free(wrong_predecessor_words);
    const wrong_predecessor = try public_data_v2.PublicDataV2.authenticate(
        wrong_predecessor_words,
    );
    try std.testing.expectError(
        error.BoundaryClockMismatch,
        public_data_v2.PublicDataV2.authenticateAdjacent(&left, &wrong_predecessor),
    );

    var bad_completion = try std.testing.allocator.dupe(M31, right_words);
    defer std.testing.allocator.free(bad_completion);
    const completion_value = segment_v2.fixed_layout.completion + 4;
    support.writeU32(
        bad_completion[completion_value..][0..2],
        @import("public_data.zig").CANONICAL_SELF_LOOP_WORD ^ 1,
    );
    try std.testing.expectError(
        error.InvalidCompletionValue,
        public_data_v2.PublicDataV2.authenticate(bad_completion),
    );
}

fn expectState(
    event: public_data_v2.BoundaryEvent,
    direction: public_data_v2.Direction,
    pc: u32,
    clock: u32,
) !void {
    switch (event) {
        .registers_state => |actual| {
            try std.testing.expectEqual(direction, actual.direction);
            try std.testing.expectEqual(pc, actual.pc);
            try std.testing.expectEqual(clock, actual.clock);
        },
        else => return error.TestExpectedEqual,
    }
}

fn expectMemory(
    event: public_data_v2.BoundaryEvent,
    direction: public_data_v2.Direction,
    address_space: u1,
    address: u32,
    predecessor_clock: u32,
    value: u32,
) !void {
    switch (event) {
        .memory_access => |actual| {
            try std.testing.expectEqual(direction, actual.direction);
            try std.testing.expectEqual(address_space, actual.address_space);
            try std.testing.expectEqual(address, actual.address);
            try std.testing.expectEqual(predecessor_clock, actual.predecessor_clock);
            try std.testing.expectEqual(value, actual.value);
        },
        else => return error.TestExpectedEqual,
    }
}

const RecordingChannel = struct {
    u32_words: [12]u32 = undefined,
    u32_words_len: usize = 0,
    u32_calls: usize = 0,
    canonical_calls: usize = 0,
    canonical_words: usize = 0,

    pub fn mixU32s(self: *RecordingChannel, words: []const u32) void {
        std.debug.assert(self.u32_words_len + words.len <= self.u32_words.len);
        @memcpy(self.u32_words[self.u32_words_len..][0..words.len], words);
        self.u32_words_len += words.len;
        self.u32_calls += 1;
    }

    pub fn mixCanonicalM31Words(self: *RecordingChannel, words: []const M31) void {
        self.canonical_calls += 1;
        self.canonical_words += words.len;
    }
};

test "public data V2 cold lease authenticates once and rejects substituted views" {
    const allocator = std.testing.allocator;
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(allocator, &source);
    defer allocator.free(words);
    const expected = try public_data_v2.PublicDataV2.authenticate(words);
    const expected_metadata = try expected.metadata();
    const owned = try allocator.dupe(M31, words);
    var counters = public_data_v2.PublicDataV2.ValidationCountersV2{};
    var lease = public_data_v2.PublicDataV2.OwnedValidatedLeaseV2.adoptCold(allocator, owned, &counters) catch |err| {
        allocator.free(owned);
        return err;
    };
    defer lease.deinit();
    comptime {
        const Storage = @typeInfo(@TypeOf(lease.storage)).pointer.child;
        if (@typeInfo(Storage) != .@"opaque") @compileError("cold lease storage must be opaque");
    }
    for (0..16) |_| {
        try lease.data().validate();
        try std.testing.expectEqualDeep(expected_metadata, try lease.data().metadata());
        _ = try lease.data().eventCounts();
        _ = try @import("statement_v2.zig").nativePublicTermCounts(lease.data());
    }
    words[0] = M31.zero(); // External allocation is not the admitted allocation.
    try lease.data().validate();
    var altered = lease.data().*;
    altered.canonical_words = words;
    try std.testing.expectError(error.SourceMutation, altered.validate());
    altered = lease.data().*;
    altered.canonical_words = altered.canonical_words[0 .. altered.canonical_words.len - 1];
    try std.testing.expectError(error.SourceMutation, altered.validate());
    altered = lease.data().*;
    altered.authenticated_wire_id[0] ^= 1;
    try std.testing.expectError(error.SourceMutation, altered.validate());
    altered = lease.data().*;
    altered.retained_snapshots = std.mem.zeroes(public_data_v2.PublicDataV2.RetainedSnapshots);
    try std.testing.expectError(error.SourceMutation, altered.validate());
    const measured = counters.snapshot();
    try std.testing.expectEqual(@as(u64, 1), measured.legacy_full_authentications);
    try std.testing.expectEqual(@as(u64, 0), measured.retained_root_authentications);
    try std.testing.expect(measured.cached_view_reuses >= 80);
}

test "public data V2 cold lease rejects changed sparse values and clocks before ownership" {
    const allocator = std.testing.allocator;
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(allocator, &source);
    defer allocator.free(words);
    const view = try segment_v2.authenticateCanonicalWire(words);
    const bad_value = try allocator.dupe(M31, words);
    defer allocator.free(bad_value); // A rejected admission does not consume it.
    bad_value[view.entry_snapshot.payload_start + 2] = M31.fromCanonical(99);
    try std.testing.expectError(error.BoundaryIdentityMismatch, public_data_v2.PublicDataV2.OwnedValidatedLeaseV2.adoptCold(allocator, bad_value, null));
    const bad_clock = try allocator.dupe(M31, words);
    defer allocator.free(bad_clock);
    support.writeU32(bad_clock[segment_v2.fixed_layout.entry_register_clocks + 2 ..][0..2], 5);
    try std.testing.expectError(error.BoundaryClockOutOfRange, public_data_v2.PublicDataV2.OwnedValidatedLeaseV2.adoptCold(allocator, bad_clock, null));
}

test "public data V2 cold statement codec retains immutable admission and rejects altered authority" {
    const allocator = std.testing.allocator;
    const wire = @import("../prover/guest_precompile/ethereum_segment_artifact_statement_wire.zig");
    const native_v1 = @import("statement.zig");
    const native_v2 = @import("statement_v2.zig");
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(allocator, &source);
    defer allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    var core: native_v1.RiscVStatement = undefined;
    core.initializeDescriptorStorage();
    core.n_components = 1;
    core.component_descs[0] = .{ .family = .branch_eq, .log_size = 4, .n_rows = 3, .n_columns = 8 };
    core.n_infra = 0;
    core.public_data = try native_v2.canonicalCorePublicData(&data);
    core.initial_pc = core.public_data.initial_pc;
    core.final_pc = core.public_data.final_pc;
    core.total_steps = core.public_data.clock;
    const statement = try native_v2.RiscVStatementV2.init(core, data);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.encode(encoded.writer(allocator), &statement, 1024 * 1024);
    var counters = public_data_v2.PublicDataV2.ValidationCountersV2{};
    var decoded = try wire.decodeWithColdLease(allocator, encoded.items, 1024 * 1024, &counters);
    defer decoded.deinit();
    for (0..8) |_| try decoded.value.validate();
    try std.testing.expectEqualDeep(statement.authority_id, decoded.value.authority_id);
    try std.testing.expectEqualSlices(M31, words, decoded.lease.ownedWords());
    // The transport is still externally mutable. Its altered authority cannot
    // change the admitted owner or mint a second one.
    encoded.items[encoded.items.len - 4] ^= 1;
    try decoded.value.validate();
    try std.testing.expectError(error.StatementAuthorityMismatch, wire.decodeWithColdLease(allocator, encoded.items, 1024 * 1024, null));
    try std.testing.expectEqual(@as(u64, 1), counters.snapshot().legacy_full_authentications);
}
