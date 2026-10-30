//! Preparation/geometry tests, NOT mixed-original soundness qualification.
const std = @import("std");
const Plan = @import("../block_v8_endpoint_caller_plan_v1.zig");
const P = @import("../blake3_ethereum_sha_profile.zig");
const Protocol = @import("../block_v5_precompile_protocol_v1.zig");
fn statement(a: std.mem.Allocator, keccak: u32, signer: u32, sha: u32, steps: u32) !P.admission.Statement {
    var empty = try @import("../guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, steps, Protocol.circuit_profile);
    defer empty.deinit();
    var shapes = empty.shapes();
    if (signer != 0) {
        inline for (@typeInfo(@TypeOf(shapes)).@"struct".fields) |field| if (!std.mem.eql(u8, field.name, "byte")) {
            @field(shapes, field.name) = .{ .log_size = 1, .n_rows = signer };
        };
    }
    return @import("../block_v5_precompile_witness_v1.zig").canonicalStatement(a, keccak, signer, sha, shapes);
}
const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 42700001, .cycle_count = 131072 };
test "resident caller plan retains exact arithmetic and removes WORD witness geometry" {
    const a = std.testing.allocator;
    const s = try statement(a, 890, 0, 0, frame.cycle_count);
    var plan = try Plan.Owned.init(a, &s, frame.cycle_count, frame, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 50), plan.ram.descriptors.len);
    try std.testing.expectEqual(@as(u64, 44500), plan.ram.logical_ram_accesses);
    try std.testing.expectEqual(@as(usize, 100), plan.halt_main_columns);
    try std.testing.expectEqual(plan.layout.totals[2], plan.offsets.program);
    try std.testing.expectEqual(plan.offsets.ram + 200, plan.interaction_logs.len);
    for (plan.ram.descriptors, 0..) |descriptor, i| {
        try std.testing.expectEqual(@as(usize, i + 1), descriptor.slot);
        try std.testing.expectEqual(@as(u32, 14), descriptor.log_size);
        for (plan.interaction_logs[plan.offsets.ram + 4 * i ..][0..4]) |log| try std.testing.expectEqual(descriptor.log_size, log);
    }
    try std.testing.expectEqual(@as(u32, 2204), s.ethereum.components[0].main_columns);
    try std.testing.expectEqual(@as(u32, 4164), s.ethereum.components[0].interaction_columns);
    inline for (.{ "inputs", "traces", "first", "access_root", "witness_logs" }) |name| try std.testing.expect(!@hasField(Plan.Owned, name));
    // RawStage is code-generated, but remains deliberately uncommitted and
    // cannot be mistaken for a verified local/memory proof.
    std.mem.doNotOptimizeAway(&@import("../block_v8_endpoint_caller_raw_stage_v1.zig").Owned.initSegment);
}
test "resident caller plan authenticates frame and all active caller families" {
    const a = std.testing.allocator;
    const s = try statement(a, 1, 1, 2, frame.cycle_count);
    var plan = try Plan.Owned.init(a, &s, frame.cycle_count, frame, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 4), P.externalCount(&plan.statement));
    try std.testing.expect(plan.layout.active[0] and plan.layout.active[13] and plan.layout.active[14]);
    var changed_frame = frame;
    changed_frame.global_first_cycle += 1;
    var changed = try Plan.Owned.init(a, &s, frame.cycle_count, changed_frame, .{});
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(plan.digest, changed.digest));
    changed_frame.global_first_cycle = 0;
    try std.testing.expectError(error.InvalidCallerEndpointFrame, Plan.Owned.init(a, &s, frame.cycle_count, changed_frame, .{}));
    try std.testing.expectError(error.EndpointCallerCellLimit, Plan.Owned.init(a, &s, frame.cycle_count, frame, .{ .max_raw_cells = 1 }));
    try std.testing.expectError(error.InvalidEndpointCallerLimits, Plan.Owned.init(a, &s, frame.cycle_count, frame, .{ .max_external_calls = 3 }));
}
fn allocationCase(a: std.mem.Allocator, s: *const P.admission.Statement) !void {
    var plan = try Plan.Owned.init(a, s, frame.cycle_count, frame, .{});
    defer plan.deinit();
}
test "resident caller plan releases every partial allocation" {
    const s = try statement(std.testing.allocator, 1, 0, 0, frame.cycle_count);
    try allocationCase(std.testing.allocator, &s);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{&s});
}
fn columnsDigest(columns: []const @import("stwo_prover_engine").pcs.ColumnEvaluation) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| h.update(std.mem.sliceAsBytes(column.values));
    return h.finalResult();
}
test "resident raw caller stage owns actual Keccak SHA and recovery rows beyond runner destruction" {
    const a = std.testing.allocator;
    const Elf = @import("../../runner/guest_precompile/test_elf.zig");
    const Raw = @import("../block_v8_endpoint_caller_raw_stage_v1.zig");
    inline for (.{ .keccak, .sha, .recovery }) |kind| {
        const source = if (kind == .recovery) Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1) else Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
        const elf = Elf.withReleaseAbi(source.len, &source);
        var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
        var session_live = true;
        defer if (session_live) session.deinit();
        var start = try session.startSegment(if (kind == .keccak) 4 else if (kind == .sha) 3 else 2);
        defer start.deinit();
        var segment = try session.resumeSegment(start.base.continuation.?, 1);
        var segment_live = true;
        defer if (segment_live) segment.deinit();
        try std.testing.expectError(error.OutOfMemory, Raw.Owned.initSegment(a, &segment, .{ .max_live_bytes = 1 }));
        const raw = try Raw.Owned.initSegment(a, &segment, .{});
        defer raw.deinit();
        try std.testing.expectEqual(@as(u32, 1), P.externalCount(&raw.plan.statement));
        try std.testing.expectEqual(@as(usize, 0), raw.plan.offsets.arithmetic);
        const digest = columnsDigest(raw.main);
        segment.deinit();
        segment_live = false;
        session.deinit();
        session_live = false;
        try std.testing.expectEqual(digest, columnsDigest(raw.main));
        try std.testing.expect(std.meta.eql(raw.witness.statement, raw.plan.statement));
        try std.testing.expect(raw.plan.ram.logical_ram_accesses > 0);
    }
}
