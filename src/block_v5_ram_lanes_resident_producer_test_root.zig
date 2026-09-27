//! CPU-only admission/ownership/claim parity. No device or proof is opened.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("frontends/riscv/prover/block_v5_ram_lanes_resident_source_v1.zig");
const Replay = @import("frontends/riscv/prover/block_v5_ram_lanes_replay_v1.zig");
const Protocol = @import("frontends/riscv/prover/block_v5_ram_lanes_protocol_v1.zig");
const Trace = @import("frontends/riscv/air/block/word_memory_lanes_trace_v1.zig");
const Proof = @import("frontends/riscv/prover/block_v5_ram_lanes_proof_v1.zig");
const Interaction = @import("frontends/riscv/prover/block_v5_ram_lanes_interaction_v1.zig");
const Range = @import("frontends/riscv/prover/block_v5_range16_v1.zig");
const Columns = @import("backends/metal/runtime/secure_resident_columns_v1.zig");
const Q = core.fields.qm31.QM31;
const T = @import("frontends/riscv/air/block/memory_transition.zig").Transition;
const events = [_]T{
    .{ .space = 1, .address = 0x1000, .clock = 0x1_ffff_ffff, .before = 0xffff_ffff, .after = 8 },
    .{ .space = 1, .address = 0x1000, .clock = 0x2_0000_0000, .before = 8, .after = 9 },
    .{ .space = 1, .address = 0x1004, .clock = 1, .before = 10, .after = 11 },
    .{ .space = 1, .address = 0x1004, .clock = std.math.maxInt(u64) - 1, .before = 11, .after = 12 },
    .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 13, .after = 14 },
};
fn geometry() Protocol.Claim {
    return .{ .first_event = 0, .total_events = events.len, .events = events.len, .row_log = 3, .first = events[0], .last = events[events.len - 1], .preceding = null };
}
test "RAM resident metadata preserves full clocks and admits4096-row tiny tails before collection" {
    const claim = geometry();
    const words = try Source.metadata(claim);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), words[15]);
    try std.testing.expectEqual(@as(u32, 1), words[16]);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), words[17]);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), words[21]);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), words[22]);
    const Backend = struct {
        pub const RamLaneResident = struct {
            pub const MIN_ROW_LOG: u32 = 12;
        };
    };
    const admitted = try Replay.admittedLimits(Backend, .{ .minimum_row_log = 1, .maximum_row_log = 22, .max_instances = 8 });
    try std.testing.expectEqual(@as(u32, 12), admitted.minimum_row_log);
    var plan = try @import("frontends/riscv/prover/block_v5_ram_lanes_replay_plan_v1.zig").sizes(std.testing.allocator, events.len, admitted);
    defer plan.deinit();
    try std.testing.expectEqualSlices(u32, &.{4096}, plan.capacities);
    try std.testing.expectError(error.InvalidV5RamReplayLimits, Replay.admittedLimits(Backend, .{ .minimum_row_log = 1, .maximum_row_log = 11, .max_instances = 8 }));
}
test "RAM resident streaming histogram matches typed lane witness for high clocks and odd padding" {
    const a = std.testing.allocator;
    var trace = try Trace.Trace.init(a, geometry(), .{ .max_row_log = 3, .max_events = events.len, .max_owned_bytes = 1 << 20 });
    defer trace.deinit();
    var streamed = try Range.Counter.init(a);
    defer streamed.deinit();
    var previous: ?T = null;
    for (events) |event| {
        try Source.addRangeRequests(&streamed, previous, event);
        try trace.append(event);
        previous = event;
    }
    try trace.seal();
    var reference = try Range.Counter.init(a);
    defer reference.deinit();
    const requests = try Proof.collectCounter(&trace, &reference);
    try std.testing.expectEqual(requests, streamed.total);
    try std.testing.expectEqualSlices(u32, reference.values, streamed.values);
    try std.testing.expectEqualSlices(u8, &reference.digest(), &streamed.digest());
}
test "RAM resident23-total transcript boundary preserves typed claims and rejects wrong census" {
    const a = std.testing.allocator;
    var trace = try Trace.Trace.init(a, geometry(), .{ .max_row_log = 3, .max_events = events.len, .max_owned_bytes = 1 << 20 });
    defer trace.deinit();
    for (events) |event| try trace.append(event);
    try trace.seal();
    const ch = Protocol.Challenges{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var counter = try Range.Counter.init(a);
    defer counter.deinit();
    var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
    defer generated.deinit(a);
    const c = generated.claim;
    var totals = [_]Q{ c.transition_sum, c.link_sum, c.initial_sum, c.endpoint_sum, Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast(c.endpoint_count))), Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast(c.range_count))) } ++ c.range_sums;
    try std.testing.expect(std.meta.eql(c, try Source.claim(totals, geometry(), counter.total)));
    try std.testing.expectError(error.SecureRamRangeCensusMismatch, Source.claim(totals, geometry(), counter.total + 1));
    totals[4] = Q.fromU32Unchecked(0, 1, 0, 0);
    try std.testing.expectError(error.InvalidSecureRamClaimCount, Source.claim(totals, geometry(), counter.total));
}
fn allocationFailure(a: std.mem.Allocator) !void {
    var arena = try Columns.Arena.init(a, .lane_fixed, 12, 1 << 20);
    defer arena.deinit();
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(arena.values.?.ptr) % (16 * 1024));
}
test "RAM resident aligned ingress cleans every allocation failure and preserves move alignment" {
    const a = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(a, allocationFailure, .{});
    var arena = try Columns.Arena.init(a, .lane_fixed, 12, 1 << 20);
    const values = arena.values.?;
    const descriptors = arena.columns.?;
    const backings = arena.backings.?;
    arena.transfer();
    arena.deinit();
    // Mimics the retained PCS owner, whose explicit alignment survives slice
    // coercion into []M31 and is used by rawFree on final release.
    a.rawFree(std.mem.sliceAsBytes(backings[0]), Columns.ALIGNMENT, @returnAddress());
    a.free(backings);
    a.free(descriptors);
    _ = values;
    try std.testing.expectError(error.SecureResidentColumnCap, Columns.Arena.init(a, .lane_fixed, 12, 1));
}
