//! Focused grammar/ownership/fixed-row parity, with NO proving or PoW grind.
const std = @import("std");
const core = @import("stwo_core");
const Ops = @import("../air/blake3_original_op_schedule_v1.zig");
const Cold = @import("../air/blake3_fixed_operation_recorder_v1.zig");
const Frames = @import("../air/block_v5_recursive_statement_frames_v1.zig");
const Epoch = @import("../air/block_v7_epoch_transcript_v1.zig");
const Native = @import("../air/blake3_transcript_plan.zig");
const Schema = @import("../air/blake3_pcs_operation_schema_v1.zig");
const Roots = @import("../air/blake3_root_sources.zig");
const Q = core.fields.qm31.QM31;
const PUBLIC: u32 = 4_200_089;
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    frame: Frames.Statement,
    recorder: Cold.Recorder,
    /// This fixture is consumed before it moves: frame/recorder allocators
    /// borrow the caller-owned, stable producer arena passed to init.
    fn init(arena: *std.heap.ArenaAllocator) !struct { frame: Frames.Statement, recorder: Cold.Recorder } {
        const a = arena.allocator();
        var builder = Frames.Builder{ .allocator = a, .track_root_offsets = false };
        defer builder.deinit();
        const epoch = try builder.digestWords(@splat(0x11));
        builder.mixU32s(&.{ 0x42384d58, 1 });
        try builder.check();
        const first = try builder.steps.toOwnedSlice(a);
        builder.mixFelts(&.{ Q.one(), Q.fromU32Unchecked(2, 3, 4, 5) });
        try builder.check();
        const claims = try builder.steps.toOwnedSlice(a);
        const root0 = try builder.digestWords(@splat(0x22));
        const root1 = try builder.digestWords(@splat(0x33));
        const frame: Frames.Statement = .{ .allocator = a, .words = try builder.data.toOwnedSlice(a), .felts = try builder.fields.toOwnedSlice(a), .first = first, .claims = claims, .sealed_offset = epoch, .roots_offset = .{ root0, root1, 0 } };
        var recorder: Cold.Recorder = .{ .a = a, .limits = .{} };
        recorder.mixU32s(&.{ 0x42374550, 1, 2 });
        recorder.mixPublicRoot(.{ .circuit = PUBLIC, .first_wire = epoch }, @splat(0x11));
        try recorder.skipCommittedRootsBounded(2, 4);
        try Epoch.fixed(a, &recorder);
        try frame.recordAt(&recorder, frame.first, PUBLIC);
        try recorder.universalPairs(53, 13);
        recorder.mixU32s(&.{ 0x53484157, 1 });
        try recorder.universalPairs(66, 1);
        try frame.recordAt(&recorder, frame.claims, PUBLIC);
        try recorder.suffix(.{ .commitment = .{ .slot = 2, .source = try Roots.caller(2) } });
        const suffix = [_]Schema.Operation{
            .{ .secure = .{ .role = .composition, .consumption = .one } },
            .{ .commitment = .{ .slot = 3, .source = try Roots.caller(3) } },
            .{ .secure = .{ .role = .oods, .consumption = .one } },
            .{ .sampled_values = .{ .count = 8, .source = .{ .circuit = 4_100_010, .first_wire = 0 } } },
            .{ .secure = .{ .role = .deep, .consumption = .one } },
            .{ .fri_root = .{ .layer = 0, .source = .{ .circuit = 4_100_011, .first_wire = 0 } } },
            .{ .secure = .{ .role = .{ .fri = 0 }, .consumption = .one } },
            .{ .terminal_coefficients = .{ .count = 1, .source = .{ .circuit = 4_100_012, .first_wire = 0 } } },
            .{ .pow = .{ .bits = 26, .source = .{ .circuit = 4_100_001, .first_wire = 2 } } },
            .{ .nonce = .{ .circuit = 4_100_001, .first_wire = 2 } },
            .{ .queries = .{ .count = 70, .log_domain_size = 5 } },
        };
        for (suffix) |operation| try recorder.suffix(operation);
        try recorder.check();
        return .{ .frame = frame, .recorder = recorder };
    }
};
test "original op schedule preserves old Native fixed plan IDs and all fixed rows" {
    const a = std.testing.allocator;
    for ([_]u32{ 1, 4 }) |capacity| {
        var producer = std.heap.ArenaAllocator.init(a);
        var live = true;
        defer if (live) producer.deinit();
        const fixture = try Fixture.init(&producer);
        const config: Native.Config = .{ .namespace = 1_000_000, .attempt_capacity = capacity };
        // Oracle is the EXACT old fixed() return expression, before the new
        // schedule owner and before the producer's payload storage disappears.
        var legacy = try Native.Plan.initCompact(a, config, fixture.recorder.operations.items);
        defer legacy.deinit();
        var owned = try Ops.Owned.capture(a, &fixture.frame, &fixture.recorder, config, PUBLIC, @splat(9));
        defer owned.deinit();
        producer.deinit();
        live = false;
        var compiled = try owned.compileNative(a);
        defer compiled.deinit();
        try std.testing.expectEqualDeep(legacy.id, compiled.id);
        try std.testing.expectEqualDeep(legacy.fixed.hash_metadata.?.g_rows, compiled.fixed.hash_metadata.?.g_rows);
        try std.testing.expectEqualDeep(legacy.fixed.hash_metadata.?.xor_rows, compiled.fixed.hash_metadata.?.xor_rows);
        inline for (0..6) |slot| try std.testing.expectEqualDeep(legacy.fixed.nonhash_fixed.?.fixed[slot], compiled.fixed.nonhash_fixed.?.fixed[slot]);
        try std.testing.expectEqualDeep(legacy.fixed.payload_reads, compiled.fixed.payload_reads);
        try std.testing.expectEqualDeep(legacy.fixed.draw_outputs, compiled.fixed.draw_outputs);
        try std.testing.expectEqualDeep(legacy.fixed.root_reads, compiled.fixed.root_reads);
        try std.testing.expectEqualDeep(legacy.fixed.query_outputs, compiled.fixed.query_outputs);
        try std.testing.expectEqual(@as(usize, 2), owned.first_root_count);
        try std.testing.expectEqual(@as(u32, 0x22222222), owned.frame.words[try owned.firstRootOffset(0)]);
        try std.testing.expectEqual(@as(u32, 0x33333333), owned.frame.words[try owned.firstRootOffset(1)]);
    }
}
test "original op schedule preserves Mixed67 roles and separate interval52 draws" {
    var producer = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer producer.deinit();
    const fixture = try Fixture.init(&producer);
    var owned = try Ops.Owned.capture(std.testing.allocator, &fixture.frame, &fixture.recorder, .{ .namespace = 1_000_000, .attempt_capacity = 4 }, PUBLIC, @splat(9));
    defer owned.deinit();
    var pairs: [67]u8 = @splat(0);
    var half: [2]u8 = @splat(0);
    var relation_operations: usize = 0;
    var selected_felts: usize = 0;
    var pow = false;
    var nonce = false;
    var queries = false;
    var claim_fields = false;
    for (owned.operations) |operation| switch (operation) {
        .secure => |value| if (value.output) |role| {
            try std.testing.expectEqual(@as(u32, 0), value.attempts);
            for (value.values) |word| try std.testing.expect(word.isZero());
            switch (role) {
                .universal => |index| {
                    try std.testing.expect(index < 67 and index != 52);
                    try std.testing.expect(value.consumption == .two);
                    pairs[index] += 1;
                    relation_operations += 1;
                    selected_felts += 2;
                },
                .universal_half => |part| {
                    try std.testing.expectEqual(@as(usize, 52), part.relation);
                    try std.testing.expect(value.consumption == .one);
                    half[part.half] += 1;
                    relation_operations += 1;
                    selected_felts += 1;
                },
                else => {},
            }
        },
        .pow => |value| {
            pow = value.bits == 26 and value.nonce_source != null;
        },
        .routed_integer => |value| {
            if (value.source.circuit == 4_100_001 and value.source.first_wire == 2) nonce = true;
        },
        .queries => |value| {
            queries = value.values.len == 70 and value.log_domain_size == 5 and value.export_outputs;
        },
        .routed_felts => |value| {
            if (value.source.circuit == PUBLIC) {
                claim_fields = value.values.len == 2 and value.source.first_wire == owned.frame.words.len;
                for (value.values) |field| try std.testing.expect(field.isZero());
            }
        },
        else => {},
    };
    for (pairs, 0..) |count, index| try std.testing.expectEqual(@as(u8, if (index == 52) 0 else 1), count);
    try std.testing.expectEqualDeep([2]u8{ 1, 1 }, half);
    try std.testing.expectEqual(@as(usize, 68), relation_operations);
    try std.testing.expectEqual(@as(usize, 134), selected_felts);
    try std.testing.expect(pow and nonce and queries and claim_fields);
}
test "original op schedule owns payloads and detects mutated frame nomination" {
    var producer = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer producer.deinit();
    const fixture = try Fixture.init(&producer);
    var owned = try Ops.Owned.capture(std.testing.allocator, &fixture.frame, &fixture.recorder, .{ .namespace = 1_000_000, .attempt_capacity = 1 }, PUBLIC, @splat(9));
    defer owned.deinit();
    fixture.frame.words[0] ^= 1;
    try owned.validate();
    owned.frame.words[0] ^= 1;
    try std.testing.expectError(error.MutatedOriginalOpSchedule, owned.validate());
    owned.frame.words[0] ^= 1;
    try owned.validate();
    try std.testing.expectError(error.InvalidOriginalOpScheduleRoot, owned.firstRootOffset(2));
}
test "original op schedule cheap join admission rejects role before any Native rows" {
    const Join = @import("../block_v8_endpoint_join_roster_v1.zig");
    const Source = @import("../block_v8_endpoint_join_source_v1.zig");
    const extra: [264]Q = @splat(Q.zero());
    try std.testing.expectError(error.InvalidEndpointJoinSources, Join.requireAdmission(&.{}, &extra));
    const wrong_role = [_]Source.Source{ .{ .global = undefined }, .{ .bridge = undefined }, .{ .global = undefined } };
    try std.testing.expectError(error.InvalidEndpointJoinSources, Join.requireAdmission(&wrong_role, &extra));
    const wrong_bridge = [_]Source.Source{ .{ .local = undefined }, .{ .global = undefined }, .{ .global = undefined } };
    try std.testing.expectError(error.InvalidEndpointJoinSources, Join.requireAdmission(&wrong_bridge, &extra));
}
