//! Bounded CPU subcomponent comparison on the same sorted RAM events. No
//! commitments, STARK, FRI, recursion, guest execution or GPU is performed.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Event = @import("air/block/memory_transition.zig").Transition;
const WordTrace = @import("air/block/word_memory_trace_v5.zig").Trace;
const LaneTrace = @import("air/block/word_memory_lanes_trace_v1.zig").Trace;
const Word = @import("prover/block_v5_word_memory_interaction_v1.zig");
const Lane = @import("prover/block_v5_ram_lanes_interaction_v1.zig");
const Protocol = @import("prover/block_v5_word_memory_protocol_v1.zig");
const Counter = @import("prover/block_v5_range16_v1.zig").Counter;
const LaneProtocol = @import("prover/block_v5_ram_lanes_protocol_v1.zig");
const EVENTS: usize = 32768;
const Buses = struct { transition: Q, link: Q, initial: Q, endpoint: Q, endpoint_count: u64, range_count: u64, range_sum: Q, counter_digest: [32]u8 };
const Sample = struct { trace_ns: u64, interaction_ns: u64, trace_and_interaction_bytes: usize, buses: Buses };
// Word pairs neighboring limb requests; lanes pair equal limb positions
// across events. Their global range sum and complete counter must agree,
// while individual normalized prefix planes have different partitions.
fn rangeSum(values: []const Q) Q {
    var sum = Q.zero();
    for (values) |value| sum = sum.add(value);
    return sum;
}
fn event(index: usize) Event {
    return .{ .space = 1, .address = @intCast(0x2000 + (index / 16) * 4), .clock = (@as(u64, 1) << 48) + index + 1, .before = @intCast(index % 16), .after = @intCast(index % 16 + 1) };
}
fn runWord(a: std.mem.Allocator, challenges: *const Protocol.Challenges, table: *const Word.RangeInverses) !Sample {
    var timer = try std.time.Timer.start();
    var trace = try WordTrace.init(a, .{ .first_row = 0, .total_rows = EVENTS, .rows = EVENTS, .log_size = 15, .first = event(0), .last = event(EVENTS - 1), .preceding = null });
    defer trace.deinit();
    for (0..EVENTS) |index| try trace.append(event(index));
    try trace.seal();
    const trace_ns = timer.read();
    var counter = try Counter.init(a);
    defer counter.deinit();
    timer.reset();
    var generated = try Word.generatePrepared(a, &trace, challenges, &counter, table);
    const interaction_ns = timer.read();
    defer generated.deinit(a);
    try std.testing.expect(generated.claim.register_endpoint_sum.isZero());
    try std.testing.expectEqual(@as(u64, 0), generated.claim.register_endpoint_count);
    const bytes = (39 * trace.domainSize() + generated.storage.len) * @sizeOf(M);
    return .{ .trace_ns = trace_ns, .interaction_ns = interaction_ns, .trace_and_interaction_bytes = bytes, .buses = .{ .transition = generated.claim.transition_sum, .link = generated.claim.link_sum, .initial = generated.claim.initial_sum, .endpoint = generated.claim.endpoint_sum, .endpoint_count = generated.claim.endpoint_count, .range_count = generated.claim.range_count, .range_sum = rangeSum(&generated.claim.range_sums), .counter_digest = counter.digest() } };
}
fn runLanes(a: std.mem.Allocator, challenges: *const Protocol.Challenges, table: *const Word.RangeInverses) !Sample {
    var timer = try std.time.Timer.start();
    var trace = try LaneTrace.init(a, .{ .first_event = 0, .total_events = EVENTS, .events = EVENTS, .row_log = 14, .first = event(0), .last = event(EVENTS - 1), .preceding = null }, .{ .max_row_log = 14, .max_events = EVENTS, .max_owned_bytes = 8 << 20 });
    defer trace.deinit();
    for (0..EVENTS) |index| try trace.append(event(index));
    try trace.seal();
    const trace_ns = timer.read();
    var counter = try Counter.init(a);
    defer counter.deinit();
    timer.reset();
    var generated = try Lane.generatePrepared(a, &trace, challenges, &counter, table, 16 << 20);
    const interaction_ns = timer.read();
    defer generated.deinit(a);
    try std.testing.expectEqual(@as(u64, EVENTS), generated.claim.event_count);
    const bytes = (LaneProtocol.MAIN_COLUMNS * trace.domainSize() + LaneProtocol.FIXED_COLUMNS * trace.domainSize() + generated.storage.len) * @sizeOf(M);
    return .{ .trace_ns = trace_ns, .interaction_ns = interaction_ns, .trace_and_interaction_bytes = bytes, .buses = .{ .transition = generated.claim.transition_sum, .link = generated.claim.link_sum, .initial = generated.claim.initial_sum, .endpoint = generated.claim.endpoint_sum, .endpoint_count = generated.claim.endpoint_count, .range_count = generated.claim.range_count, .range_sum = rangeSum(&generated.claim.range_sums), .counter_digest = counter.digest() } };
}
test "block-v5 RAM component benchmark paired witness interaction bus and allocation comparison" {
    const a = std.heap.page_allocator;
    const challenges = Protocol.Challenges{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    var table = try Word.RangeInverses.init(a, challenges.range16);
    defer table.deinit();
    const warm_word = try runWord(a, &challenges, &table);
    const warm_lanes = try runLanes(a, &challenges, &table);
    try std.testing.expectEqualDeep(warm_word.buses, warm_lanes.buses);
    var word_ns: [4]u64 = undefined;
    var lane_ns: [4]u64 = undefined;
    for ([_]bool{ false, true, true, false }, 0..) |lanes_first, index| {
        const first = if (lanes_first) try runLanes(a, &challenges, &table) else try runWord(a, &challenges, &table);
        const second = if (lanes_first) try runWord(a, &challenges, &table) else try runLanes(a, &challenges, &table);
        const word = if (lanes_first) second else first;
        const lanes = if (lanes_first) first else second;
        try std.testing.expectEqualDeep(word.buses, lanes.buses);
        try std.testing.expectEqualDeep(warm_word.buses, word.buses);
        word_ns[index] = word.interaction_ns;
        lane_ns[index] = lanes.interaction_ns;
        std.debug.print("RAM_COMPONENT_KERNEL sample={d} events={d} lanes_first={} word_trace_ns={d} lane_trace_ns={d} word_interaction_ns={d} lane_interaction_ns={d} word_trace_interaction_bytes={d} lane_trace_interaction_bytes={d} exact_bus_counter_parity=true scope=witness_and_interaction_only shared_inverse_setup_included=false prover_or_recursion=false\n", .{ index, EVENTS, lanes_first, word.trace_ns, lanes.trace_ns, word.interaction_ns, lanes.interaction_ns, word.trace_and_interaction_bytes, lanes.trace_and_interaction_bytes });
    }
    std.mem.sort(u64, &word_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &lane_ns, {}, std.sort.asc(u64));
    const word_median = (word_ns[1] + word_ns[2]) / 2;
    const lane_median = (lane_ns[1] + lane_ns[2]) / 2;
    std.debug.print("RAM_COMPONENT_KERNEL_MEDIAN events={d} word_interaction_ns={d} lane_interaction_ns={d} word_rows=32768 lane_rows=16384 scope=interaction_only process_peak_memory_measured=false end_to_end_proving_measured=false\n", .{ EVENTS, word_median, lane_median });
}
