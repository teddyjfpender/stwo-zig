const std = @import("std");
const core = @import("stwo_core");
const Keccak = @import("../../air/guest_precompile/keccakf_trace.zig");
const Authority = @import("../../air/guest_precompile/keccakf_authority.zig");
const Record = @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record;
const Layout = @import("../block_v7_keccak_window_layout_v1.zig");
const Memory = @import("../block_v7_keccak_window_memory_v1.zig");
const Bus = @import("../block_memory_relation_v2.zig");
fn record(input: [50]u32) Record {
    var state = Keccak.stateFromWords(input);
    Authority.permute(&state);
    var output: [50]u32 = undefined;
    for (state, 0..) |lane, i| {
        output[2 * i] = @truncate(lane);
        output[2 * i + 1] = @truncate(lane >> 32);
    }
    return .{ .execution_clock = 1, .pc = 1024, .state_ptr = 4096, .pointer_register = 5, .pointer_previous_clock = 0, .input = input, .output = output, .memory_previous_clocks = @splat(0) };
}
test "Keccak shared memory builds one witness for equal control distinct frame RAM" {
    const a = std.testing.allocator;
    const first = record(@splat(0));
    const second = record(first.output);
    const records = [_]Record{ first, second };
    var counter = try @import("../../air/guest_precompile/keccakf_multiplicities.zig").Counters.init(a);
    defer counter.deinit();
    var shard = try Keccak.generateShardForRecipe(a, &records, 0, &counter, Keccak.maximum_log_size, true);
    defer shard.deinit();
    var layout = try Layout.Owned.derive(a, &.{
        .{ .index = 1, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 4, .cycle_count = 3 }, .calls = 1 },
        .{ .index = 2, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 7, .cycle_count = 3 }, .calls = 1 },
    }, .{});
    defer layout.deinit();
    try std.testing.expectError(error.KeccakMemoryWitnessLimit, Memory.Prepared.init(a, &shard, &layout, .{ .max_witness_bytes = 1 }));
    var prepared = try Memory.Prepared.init(a, &shard, &layout, .{});
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 50 * 48 * 32 * 4), prepared.witness_bytes);
    const word = try prepared.view(1);
    const left = try Bus.decodeTransitionTuple((try word.row(0)).tuple);
    const right = try Bus.decodeTransitionTuple((try word.row(1)).tuple);
    try std.testing.expectEqual(@as(u64, 14), left.clock);
    try std.testing.expectEqual(@as(u64, 26), right.clock);
    try std.testing.expectEqual(first.input[0], left.before);
    try std.testing.expectEqual(first.output[0], left.after);
    try std.testing.expectEqual(left.after, right.before);
    try std.testing.expectEqual(second.output[0], right.after);
    try std.testing.expect(!(try word.row(27)).active);
    var bytes = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer bytes.deinit(a);
    const snapshots = try prepared.collectCounter(a, &bytes);
    var channel = core.proof_suites.Blake3.Channel{};
    const challenges = try @import("../block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    var generated = try prepared.generate(a, &challenges, snapshots, .{});
    defer generated.deinit();
    for (generated.claims) |claim| try std.testing.expectEqual(@as(u64, 2), claim.active_count);
    try std.testing.expectEqual(@as(usize, 50 * 49), generated.matrix.columns.len);
    const columns = try prepared.columns(a);
    defer a.free(columns);
    try std.testing.expectEqual(@as(usize, 50 * 48), columns.len);
}
