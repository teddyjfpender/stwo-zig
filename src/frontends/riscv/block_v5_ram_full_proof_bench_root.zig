//! Component-only CPU comparison on identical sorted RAM events. The synthetic
//! roster pins each proof to its own source seal; it does not prove a block.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const WordTrace = @import("air/block/word_memory_trace_v5.zig").Trace;
const LaneTrace = @import("air/block/word_memory_lanes_trace_v1.zig").Trace;
const Event = @import("air/block/memory_transition.zig").Transition;
const Word = @import("prover/block_v5_word_memory_proof_v1.zig");
const Lane = @import("prover/block_v5_ram_lanes_proof_v1.zig");
const WordInteraction = @import("prover/block_v5_word_memory_interaction_v1.zig");
const LaneInteraction = @import("prover/block_v5_ram_lanes_interaction_v1.zig");
const Range = @import("prover/block_v5_range16_v1.zig");
const RangeProof = @import("prover/block_v5_range16_proof_v1.zig");
const Seal = @import("prover/block_v5_source_seal_v1.zig");
const WorkPool = @import("stwo_prover_engine").work_pool;
const WordClaim = @import("air/block/memory_component.zig").Claim;
const LaneClaim = @import("prover/block_v5_ram_lanes_protocol_v1.zig").Claim;

const SMALL_EVENTS: u32 = 32_768;
const MEDIUM_EVENTS: u32 = 1 << 16;
const QUARTER_MILLION_EVENTS: u32 = 1 << 18;
const LARGE_EVENTS: u32 = 1 << 20;
const CAPACITY_EVENTS: u32 = 1 << 22;
const Stats = struct { first_ns: u64, inverse_ns: u64, proof_ns: u64, verify_ns: u64 };
const Profile = enum { diagnostic, query70, canonical };

fn event(index: u32) Event {
    return .{ .space = 1, .address = 0x2000 + (index / 16) * 4, .clock = (@as(u64, 1) << 48) + index + 1, .before = index % 16, .after = index % 16 + 1 };
}

fn config(profile: Profile) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (profile == .canonical) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (profile == .diagnostic) 8 else 70), .lifting_log_size = null };
}

const Fixture = struct {
    pins: Seal.Pins,
    entries: [6]Seal.Entry,
    sealed: Seal.Sealed,
};

fn fixture(memory_entry: Seal.Entry, config_value: core.pcs.PcsConfig) !Fixture {
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family|
        counts[@intFromEnum(family) - 1] = 1;
    const pins = Seal.Pins{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .native_template_id = @splat(3),
        .program_root = @splat(4),
        .program_plan_digest = @splat(5),
        .memory_plan_digest = @splat(6),
        .initial_source_plan_digest = @splat(7),
        .expected_final_rw_root = @splat(8),
        .rw_endpoint_plan_digest = @splat(9),
        .register_endpoint_plan_digest = @splat(10),
        .register_custody_mode = 1,
        .config = config_value,
        .counts = counts,
    };
    const entries = [6]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
        memory_entry,
        .{ .family = .memory_range, .index = 0, .instance_id = RangeProof.instanceId(@splat(23), 0), .roots = .{ @splat(24), @splat(25) } },
    };
    return .{ .pins = pins, .entries = entries, .sealed = try Seal.seal(pins, &entries) };
}

fn runWord(a: std.mem.Allocator, profile: Profile, events: u32) !Stats {
    const claim = WordClaim{ .first_row = 0, .total_rows = events, .rows = events, .log_size = std.math.log2_int(u32, events), .first = event(0), .last = event(events - 1), .preceding = null };
    var trace = try WordTrace.init(a, claim);
    defer trace.deinit();
    for (0..events) |index| try trace.append(event(@intCast(index)));
    try trace.seal();
    const cfg = try config(profile);
    var counter = try Range.Counter.init(a);
    defer counter.deinit();
    var timer = try std.time.Timer.start();
    var first = try Word.ForBackend(Cpu).commitFirstRound(a, &trace, &counter, 0, cfg, true);
    defer first.deinit(a);
    const first_ns = timer.read();
    const memory_entry = Seal.Entry{ .family = .memory, .index = 0, .instance_id = Word.instanceId(claim, 0), .roots = first.roots() };
    const sealed = try fixture(memory_entry, cfg);
    const challenges = try @import("prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, sealed.sealed);
    timer.reset();
    var table = try WordInteraction.RangeInverses.init(a, challenges.range16);
    const inverse_ns = timer.read();
    defer table.deinit();
    timer.reset();
    const proof = try Word.ForBackend(Cpu).provePrepared(a, &first, &trace, sealed.sealed, sealed.pins, &sealed.entries, 0, &table);
    const proof_ns = timer.read();
    timer.reset();
    _ = try Word.ForBackend(Cpu).verifyOwned(a, proof, claim, sealed.sealed, sealed.pins, &sealed.entries, 0, first.roots());
    return .{ .first_ns = first_ns, .inverse_ns = inverse_ns, .proof_ns = proof_ns, .verify_ns = timer.read() };
}

fn runLane(a: std.mem.Allocator, profile: Profile, events: u32) !Stats {
    const claim = LaneClaim{ .first_event = 0, .total_events = events, .events = events, .row_log = std.math.log2_int(u32, events) - 1, .first = event(0), .last = event(events - 1), .preceding = null };
    var trace = try LaneTrace.init(a, claim, .{ .max_row_log = claim.row_log, .max_events = events, .max_owned_bytes = @as(usize, events) * 256 });
    defer trace.deinit();
    for (0..events) |index| try trace.append(event(@intCast(index)));
    try trace.seal();
    const cfg = try config(profile);
    var counter = try Range.Counter.init(a);
    defer counter.deinit();
    var timer = try std.time.Timer.start();
    var first = try Lane.ForBackend(Cpu).commitFirstRoundWithCounter(a, &trace, 0, cfg, true, .{}, &counter);
    defer first.deinit(a);
    const first_ns = timer.read();
    const sealed = try fixture(try first.pin.entry(), cfg);
    const challenges = try @import("prover/block_v5_ram_lanes_protocol_v1.zig").Challenges.draw(a, sealed.sealed);
    timer.reset();
    var table = try LaneInteraction.RangeInverses.init(a, challenges.range16);
    const inverse_ns = timer.read();
    defer table.deinit();
    timer.reset();
    const proof = try Lane.ForBackend(Cpu).provePrepared(a, &first, &trace, first.pin, sealed.sealed, sealed.pins, &sealed.entries, &table, .{});
    const proof_ns = timer.read();
    timer.reset();
    _ = try Lane.ForBackend(Cpu).verifyOwned(a, proof, first.pin, sealed.sealed, sealed.pins, &sealed.entries, .{});
    return .{ .first_ns = first_ns, .inverse_ns = inverse_ns, .proof_ns = proof_ns, .verify_ns = timer.read() };
}

test "block-v5 RAM full component proof comparison" {
    const a = std.heap.page_allocator;
    const events: u32 = if (std.process.hasEnvVarConstant("STWO_BLOCK_4M_EVENTS")) CAPACITY_EVENTS else if (std.process.hasEnvVarConstant("STWO_BLOCK_MILLION_EVENTS")) LARGE_EVENTS else if (std.process.hasEnvVarConstant("STWO_BLOCK_QUARTER_MILLION_EVENTS")) QUARTER_MILLION_EVENTS else if (std.process.hasEnvVarConstant("STWO_BLOCK_64K_EVENTS")) MEDIUM_EVENTS else SMALL_EVENTS;
    const large = events != SMALL_EVENTS;
    const profile: Profile = if (std.process.hasEnvVarConstant("STWO_BLOCK_CANONICAL_BENCH")) .canonical else if (std.process.hasEnvVarConstant("STWO_BLOCK_QUERY70_BENCH")) .query70 else .diagnostic;
    const pooled = std.process.hasEnvVarConstant("STWO_BLOCK_POOL8_BENCH");
    var pool: WorkPool.WorkPool = undefined;
    if (pooled) try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer if (pooled) pool.deinit();
    var binding: ?WorkPool.ScopedPoolBinding = if (pooled) try .init(&pool) else null;
    defer if (binding) |*bound| bound.deinit();
    var word_total_ns: [4]u64 = undefined;
    var lane_total_ns: [4]u64 = undefined;
    const repeat_large = std.process.hasEnvVarConstant("STWO_BLOCK_REPEAT_LARGE");
    const orders: []const bool = if ((large and !repeat_large) or (profile == .canonical and !pooled)) &.{false} else &.{ false, true, true, false };
    for (orders, 0..) |lane_first, index| {
        const first = if (lane_first) try runLane(a, profile, events) else try runWord(a, profile, events);
        const second = if (lane_first) try runWord(a, profile, events) else try runLane(a, profile, events);
        const word = if (lane_first) second else first;
        const lane = if (lane_first) first else second;
        word_total_ns[index] = word.first_ns + word.inverse_ns + word.proof_ns;
        lane_total_ns[index] = lane.first_ns + lane.inverse_ns + lane.proof_ns;
        std.debug.print("RAM_PROOF_COMPONENT sample={d} events={d} queries={d} pow_bits={d} pool_workers={d} lane_first={} word_first_ns={d} lane_first_ns={d} word_inverse_ns={d} lane_inverse_ns={d} word_proof_ns={d} lane_proof_ns={d} word_verify_ns={d} lane_verify_ns={d} word_total_ns={d} lane_total_ns={d} each_proof_verified=true block_or_global_closure=false\n", .{ index, events, if (profile == .diagnostic) @as(u32, 8) else 70, if (profile == .canonical) @as(u32, 26) else 0, if (pooled) @as(u32, 8) else 0, lane_first, word.first_ns, lane.first_ns, word.inverse_ns, lane.inverse_ns, word.proof_ns, lane.proof_ns, word.verify_ns, lane.verify_ns, word_total_ns[index], lane_total_ns[index] });
    }
    if (orders.len == 1) return;
    std.mem.sort(u64, &word_total_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &lane_total_ns, {}, std.sort.asc(u64));
    std.debug.print("RAM_PROOF_COMPONENT_MEDIAN events={d} word_total_ns={d} lane_total_ns={d} scope=component_only exact_security={}\n", .{ events, (word_total_ns[1] + word_total_ns[2]) / 2, (lane_total_ns[1] + lane_total_ns[2]) / 2, profile == .canonical });
}
