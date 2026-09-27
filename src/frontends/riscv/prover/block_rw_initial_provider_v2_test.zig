//! Focused native and quotient checks for the block-v2 RW initial provider.
const std = @import("std");
const core = @import("stwo_core");
const memory_state = @import("../runner/memory_state.zig");
const snapshot_mod = @import("../recursion/air/blake3_memory_snapshot.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const bus = @import("block_memory_relation_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const provider = @import("block_rw_initial_provider_v2.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Plan = provider.Plan;
const Point = provider.Point;
const build = provider.build;
const interactionConstraints = provider.interactionConstraints;
const trustedFixedTrace = provider.trustedFixedTrace;
const readSecure = provider.readSecure;

test "RW typed AIR semantic digest" {
    const digest = try @import("block_rw_initial_air_v2.zig").computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(provider.SEMANTIC_DIGEST, digest);
}

test "RW provider real fixture census" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, "autoresearch/notes/2026-09-24-ethereum-block-delivery/exact-three-segment-v1/memory-first-touch.bin", 1 << 20);
    defer a.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), bytes.len % 10);
    var addresses: std.ArrayList(u32) = .empty;
    defer addresses.deinit(a);
    for (0..bytes.len / 10) |i| {
        const row = bytes[i * 10 ..][0..10];
        if (row[9] != 1 and row[9] != 2) continue;
        try std.testing.expectEqual(@as(u8, 1), row[0]);
        try addresses.append(a, std.mem.readInt(u32, row[1..5], .little));
    }
    try std.testing.expectEqual(@as(usize, 4716), addresses.items.len);
    var namespace: u32 = 1;
    for (0..std.math.divCeil(usize, addresses.items.len, provider.MAX_FIRST_TOUCH_KEYS_PER_CHUNK) catch unreachable) |chunk_index| {
        const start = chunk_index * provider.MAX_FIRST_TOUCH_KEYS_PER_CHUNK;
        const selected = addresses.items[start..@min(start + provider.MAX_FIRST_TOUCH_KEYS_PER_CHUNK, addresses.items.len)];
        const caller_base = namespace;
        const path_namespace = caller_base + @as(u32, @intCast(selected.len)) + 1;
        const result = try provider.censusAddresses(a, selected, caller_base, path_namespace);
        std.debug.print("RW_CENSUS chunk={d} keys={d} nodes={d} frontier={d} g={d} xor={d} boundary={d} bridge={d} route={d} private={d} total={d} namespace_end={d}\n", .{
            chunk_index, result.first_touch_keys, result.computed_nodes, result.frontier_nodes,
            result.g_rows, result.xor_rows, result.boundary_rows, result.bridge_rows,
            result.route_rows, result.private_rows, result.totalHashRows(), result.namespace_end,
        });
        namespace = result.namespace_end + 1;
    }
}
test "continuation first-touch provider includes public input and binds typed leaf callers" {
    const a = std.testing.allocator;
    var definition = try build(a);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 3), definition.arena.effectsView().len);
    _ = try @import("../recursion/air/universal_relation_binding.zig").Binding(@import("block_rw_initial_air_v2.zig")).authenticate(&definition);
    const layout = memory_state.MemoryLayout{
        .program_base = 0,
        .program_end = 0x100,
        .data_base = 0x1000,
        .data_end = 0x2000,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x4000,
        .io_end = 0x5000,
        .input_base = 0x2000,
        .input_end = 0x3000,
        .output_len_addr = 0x4000,
        .output_data_addr = 0x4004,
        .output_base = 0x4000,
        .output_end = 0x5000,
    };
    var words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x12345678, .final_word = 0x12345678, .final_clock = 0 },
        .{ .addr = 0x2000, .initial_word = 0xdeadbeef, .final_word = 0xdeadbeef, .final_clock = 0, .role = .{ .is_public_input = true } },
    };
    const snapshot = memory_state.Snapshot{ .layout = layout, .segment_role = .single(), .words = &words };
    var projection = try snapshot_mod.fromSnapshot(a, &snapshot, .entry, .continuation);
    defer projection.deinit();
    const machine = try spans.MachineState.init(0, @splat(0), projection.root, .{ .bytes = @splat(0) });
    const complete = try spans.CompleteExecution.init(.{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, machine, machine, .{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, 1);
    const job = try spans.JobContext.init(complete, 1);
    var plan = try Plan.init(a, &snapshot, job, &.{ 0x1000, 0x2000, 0x2004 }, 100, 200);
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 0x12345678), (try bus.decodeInitialTuple(try plan.tuple(0))).value);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), (try bus.decodeInitialTuple(try plan.tuple(1))).value);
    try std.testing.expectEqual(@as(u32, 0), (try bus.decodeInitialTuple(try plan.tuple(2))).value);
    try std.testing.expectEqual(@as(u32, 0x2000 / 4), plan.path_inputs[1].address);
    try std.testing.expectEqual(@as(u32, 101), plan.path_inputs[1].caller.circuit);
    const census = try plan.census();
    try std.testing.expectEqualDeep(census, try provider.censusAddresses(a, &.{ 0x1000, 0x2000, 0x2004 }, 100, 200));
    try std.testing.expectEqual(@as(usize, 3), census.first_touch_keys);
    try std.testing.expect(census.computed_nodes >= 3 and census.totalHashRows() > 0);
    var borrowed = try Plan.initBorrowed(a, &projection, layout, job, &.{0x1000}, 300, 400);
    defer borrowed.deinit();
    try std.testing.expectEqualDeep(projection.root, borrowed.source.root);
    var trace = try plan.trace();
    defer trace.deinit();
    var trusted = try trustedFixedTrace(a, job, layout, &.{ 0x1000, 0x2000, 0x2004 }, 100, 200, plan.rosterDigest());
    defer trusted.deinit();
    for (trace.fixed, trusted.columns) |from_witness, from_roster| try std.testing.expectEqualSlices(M, from_witness, from_roster);
    var bad_digest = plan.rosterDigest();
    bad_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedInitialRwRoster, trustedFixedTrace(a, job, layout, &.{ 0x1000, 0x2000, 0x2004 }, 100, 200, bad_digest));
    const challenges = bus.Challenges{
        .transition = undefined,
        .link = undefined,
        .initial = @import("../air/relation_challenges.zig").RelationElements(bus.INITIAL_ARITY).dummy(),
        .universal_prefix = undefined,
    };
    var interaction = try plan.interaction(&challenges);
    defer interaction.deinit();
    try std.testing.expect(interaction.claim.initial_sum.eql(try plan.initialClaim(&challenges)));
    const adapter = try @import("block_rw_initial_provider_stark_v2.zig").Component.init(interaction.claim, &challenges, .{});
    _ = adapter.asProverComponent();
    const size: usize = @as(usize, 1) << @intCast(trace.log_size);
    for (0..size) |logical| {
        const index = framework.committedRow(logical, trace.log_size);
        const prev_index = framework.committedRow(if (logical == 0) size - 1 else logical - 1, trace.log_size);
        var tuple: [bus.INITIAL_ARITY]Q = @splat(Q.zero());
        tuple[0] = Q.one();
        for (0..4) |i| {
            tuple[1 + i] = Q.fromBase(trace.fixed[i][index]);
            tuple[5 + i] = Q.fromBase(trace.main[i][index]);
        }
        const point = Point{
            .active = Q.fromBase(trace.fixed[6][index]),
            .initial_emit = Q.fromBase(trace.fixed[7][index]),
            .first = Q.fromBase(trace.fixed[8][index]),
            .domain_last = Q.fromBase(trace.fixed[9][index]),
            .tuple = tuple,
            .term = readSecure(&interaction.columns, 0, index),
            .prefix = readSecure(&interaction.columns, 4, index),
            .previous_prefix = readSecure(&interaction.columns, 4, prev_index),
        };
        for (try interactionConstraints(&challenges, point, interaction.claim)) |identity| try std.testing.expect(identity.isZero());
        if (logical == 0) {
            var forged = point;
            forged.tuple[5] = forged.tuple[5].add(Q.one());
            try std.testing.expect(!(try interactionConstraints(&challenges, forged, interaction.claim))[0].isZero());
        }
    }
    try std.testing.expectError(error.UnsortedInitialRwRoster, Plan.init(a, &snapshot, job, &.{ 0x2000, 0x1000 }, 100, 200));
    var changed = job;
    changed.complete.initial_state.rw_memory.bytes[0] ^= 1;
    try std.testing.expectError(error.InitialRwRootMismatch, Plan.init(a, &snapshot, changed, &.{0x1000}, 100, 200));
}
