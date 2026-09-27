//! Source-only metadata/algebra/ownership checks. Literal pins are independently
//! admitted proposals; no Fresh/Verified token is fabricated and no proof runs.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Plan = @import("block_v5_ram_range_forest_plan_v1.zig");
const Algebra = @import("air/block_v5_ram_range_forest_algebra_v1.zig");
const Final = @import("air/block_v5_source_ram_forest_join_algebra_v1.zig");
const Lane = @import("../prover/block_v5_ram_lanes_proof_v1.zig");
const Plans = @import("../prover/block_v5_ram_lanes_plan_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Forest = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
const Batch = @import("../prover/block_v5_memory_source_batch_protocol_v1.zig");
const Auth = @import("../prover/block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("../prover/block_v5_initial_sources_v1.zig");
const Defaults = @import("../prover/block_v5_memory_source_batch_defaults_v1.zig");
const R = @import("air/composition_graph_recorder.zig");
fn admission() !Batch.Admission {
    const empty = Defaults.get().defaults[0].bytes;
    const sha = Initial.sha256("");
    const source = try Auth.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
        .initial_rw_root = empty,
        .initial_registers = @splat(0),
        .public_input_sha256 = sha,
        .public_input_len = 0,
        .input_words = .{ .sha256 = sha, .records = 0 },
        .rw_words = .{ .sha256 = sha, .records = 0 },
        .first_touches = .{ .sha256 = sha, .records = 0 },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = empty, .endpoints = .{ .sha256 = sha, .records = 0 } }, @splat(8), .{});
    return Batch.Admission.init(source, .{});
}
const Sink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnclosedRecursiveMemoryFixture;
    }
};
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
fn sourceClaims() [Forest.CLAIM_COUNT]Q {
    var out: [Forest.CLAIM_COUNT]Q = @splat(Q.zero());
    out[6] = scalar(7); // open initial
    out[7] = scalar(11); // open endpoint
    out[11] = scalar(13); // indexed opposite original fold
    out[12] = out[11].neg();
    inline for (.{ 2, 3, 4 }, .{ 13, 14, 15 }) |raw, fold| {
        out[raw] = scalar(raw);
        out[fold] = out[raw].neg();
    }
    out[21] = Q.one(); // mandatory original one-root census even empty image
    return out;
}
fn event(ordinal: u64) Event {
    return .{ .space = 1, .address = 0x8000_0000, .clock = (@as(u64, 1) << 40) + ordinal + 1, .before = 7, .after = 7 };
}
fn pin(index: u32, count: u32, events: u32, row_log: u32) Lane.Pin {
    const first = @as(u64, index) * events;
    return .{ .claim = .{ .first_event = first, .total_events = @as(u64, count) * events, .events = events, .row_log = row_log, .first = event(first), .last = event(first + events - 1), .preceding = if (index == 0) null else event(first - 1) }, .index = index, .roots = .{ @splat(8), @splat(9) }, .request_count = 14 * @as(u64, events) - @as(u64, if (index == 0) 4 else 0), .counter_digest = @splat(10), .config = Base.PCS_CONFIG };
}
fn topology(a: std.mem.Allocator, count: u32, events: u32, row_log: u32) !void {
    const pins = try a.alloc(Lane.Pin, count);
    defer a.free(pins);
    for (pins, 0..) |*p, index| p.* = pin(@intCast(index), count, events, row_log);
    var range = try Plans.rangePlan(a, pins, @as(u64, count) * events, .{});
    defer range.deinit(a);
    var forest = try Plan.derive(a, pins, &range, .{});
    defer forest.deinit();
    try forest.require(a, pins, &range, .{});
    try std.testing.expectEqual(try Plan.requiredNodes(range.shards), forest.nodes.len);
    const seen_ram = try a.alloc(bool, count);
    defer a.free(seen_ram);
    @memset(seen_ram, false);
    const seen_range = try a.alloc(bool, range.shards.len);
    defer a.free(seen_range);
    @memset(seen_range, false);
    for (forest.nodes, 0..) |node, index| {
        try std.testing.expect(node.child_count >= 2 and node.child_count <= 4);
        var providers: u32 = 0;
        for (node.children[0..node.child_count]) |ref| switch (ref) {
            .ram => |i| {
                try std.testing.expect(!seen_ram[i]);
                seen_ram[i] = true;
                try std.testing.expect(node.kind != .aggregate);
            },
            .range => |i| {
                try std.testing.expect(!seen_range[i]);
                seen_range[i] = true;
                providers += 1;
                try std.testing.expect(node.kind == .shard and i == node.shards.first);
            },
            .node => |i| try std.testing.expect(i < index),
        };
        try std.testing.expectEqual(@as(u32, if (node.kind == .shard) 1 else 0), providers);
    }
    for (seen_ram) |seen| try std.testing.expect(seen);
    for (seen_range) |seen| try std.testing.expect(seen);
    if (count == 0) {
        try std.testing.expect(forest.root == null and forest.nodes.len == 0);
    } else {
        const root = forest.nodes[forest.root.?];
        try std.testing.expectEqual(count, root.lanes.count);
        try std.testing.expectEqual(@as(u32, 0), root.lanes.first);
        try std.testing.expectEqual(range.shards.len, root.shards.count);
        try std.testing.expectEqual(@as(u64, count) * events, root.events);
        if (count == 160 and events == 1 << 20) try std.testing.expect(root.requests > core.fields.m31.Modulus);
        var changed = forest;
        changed.root = null;
        if (changed.require(a, pins, &range, .{})) |_| return error.TestExpectedError else |failure| {
            if (failure != error.UntrustedRamRangeForestTopology) return failure;
        }
    }
}
test "RAM range forest: minimum ordered fanin4 topology for empty and carry edges" {
    for (0..258) |count| try topology(std.testing.allocator, @intCast(count), 4, 2);
}
test "RAM range forest: independent shards preserve u64 aggregate request census" {
    try topology(std.testing.allocator, 85, 1 << 20, 19);
    try topology(std.testing.allocator, 160, 1 << 20, 19);
}
fn topologyFault(a: std.mem.Allocator) !void {
    try topology(a, 9, 4, 2);
}
test "RAM range forest: every topology allocation failure rolls back ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, topologyFault, .{});
}
test "RAM range forest: topology resource and original ordinal failures are strict" {
    var pins = [_]Lane.Pin{ pin(0, 2, 4, 2), pin(1, 2, 4, 2) };
    var range = try Plans.rangePlan(std.testing.allocator, &pins, 8, .{});
    defer range.deinit(std.testing.allocator);
    try std.testing.expectError(error.RamRangeForestResourceLimit, Plan.derive(std.testing.allocator, &pins, &range, .{ .max_nodes = 0 }));
    try std.testing.expectError(error.RamRangeForestResourceLimit, Plan.derive(std.testing.allocator, &pins, &range, .{ .max_metadata_bytes = 1 }));
    pins[1].claim.preceding.?.clock += 1;
    try std.testing.expectError(error.MemoryClockOrder, Plan.derive(std.testing.allocator, &pins, &range, .{}));
}
fn equationNode(kind: Plan.Kind, refs: []const Plan.Ref) Plan.Node {
    var out = Plan.Node{ .kind = kind, .children = @splat(.{ .ram = 0 }), .child_count = @intCast(refs.len), .lanes = .{ .first = 0, .count = 1 }, .shards = .{ .first = 0, .count = if (kind == .partial) 0 else 1 }, .events = 4, .requests = 52 };
    @memcpy(out.children[0..refs.len], refs);
    return out;
}
fn requester() [22]Q {
    var values: [22]Q = @splat(Q.zero());
    for (&values, 0..) |*q, i| q.* = scalar(@intCast(i));
    return values;
}
fn supply(values: [22]Q) [22]Q {
    var result: [22]Q = @splat(Q.zero());
    for (values[5..]) |q| result[0] = result[0].sub(q);
    return result;
}
fn closed(values: [22]Q) [22]Q {
    var result = values;
    @memset(result[5..], Q.zero());
    return result;
}
test "RAM range forest: all17 requester planes propagate and close only in own shard" {
    const values = requester();
    const provider = supply(values);
    const partial = equationNode(.partial, &.{ .{ .ram = 0 }, .{ .ram = 1 } });
    const shard = equationNode(.shard, &.{ .{ .ram = 0 }, .{ .range = 0 } });
    const aggregate = equationNode(.aggregate, &.{ .{ .node = 0 }, .{ .node = 1 } });
    const zero: [22]Q = @splat(Q.zero());
    var sink = Sink{};
    try Algebra.close(Q, &sink, partial, &.{ values, zero }, values);
    try Algebra.close(Q, &sink, shard, &.{ values, provider }, closed(values));
    try Algebra.close(Q, &sink, aggregate, &.{ closed(values), zero }, closed(values));
    for (5..22) |plane| {
        var changed = values;
        changed[plane] = changed[plane].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, partial, &.{ changed, zero }, values));
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, shard, &.{ changed, provider }, closed(values)));
    }
    var short = provider;
    short[0] = short[0].add(Q.one());
    var excess = provider;
    excess[0] = excess[0].sub(Q.one());
    try std.testing.expect(short[0].add(excess[0]).eql(provider[0].add(provider[0])));
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, shard, &.{ values, short }, closed(values)));
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, shard, &.{ values, excess }, closed(values)));
    var residual = zero;
    residual[5] = Q.one();
    var opposite = zero;
    opposite[5] = Q.one().neg();
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, aggregate, &.{ residual, opposite }, zero));
}
test "RAM range forest: final PAGE signs and transition stay exact and open" {
    const admitted = try admission();
    const source = sourceClaims();
    var memory: [22]Q = @splat(Q.zero());
    memory[0] = scalar(71);
    memory[2] = source[6].neg();
    memory[3] = source[7];
    var sink = Sink{};
    try std.testing.expect((try Final.close(Q, &sink, &admitted, source, memory)).eql(memory[0]));
    for (0..22) |i| {
        var changed = source;
        changed[i] = changed[i].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Final.close(Q, &sink, &admitted, changed, memory));
    }
    for (1..22) |i| {
        var changed = memory;
        changed[i] = changed[i].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Final.close(Q, &sink, &admitted, source, changed));
    }
    var empty: [22]Q = @splat(Q.zero());
    empty[21] = Q.one();
    try std.testing.expect((try Final.close(Q, &sink, &admitted, empty, @splat(Q.zero()))).isZero());
}
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    fn deinit(self: *@This()) void {
        self.circuit.deinit();
        self.arena.deinit();
    }
    fn evaluate(self: *@This()) !void {
        try self.circuit.evaluateInto(self.inputs, self.values);
    }
};
const SymbolicSink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
fn symbolic(a: std.mem.Allocator) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const values = requester();
    const concrete = values ++ supply(values) ++ closed(values);
    var symbols: [concrete.len]R.Scalar = undefined;
    for (&symbols) |*symbol| symbol.* = (try builder.input()).value;
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    var sink = SymbolicSink{ .builder = &builder };
    try Algebra.close(R.Scalar, &sink, equationNode(.shard, &.{ .{ .ram = 0 }, .{ .range = 0 } }), &.{ symbols[0..22].*, symbols[22..44].* }, symbols[44..66].*);
    try builder.check();
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try temp.dupe(Q, &concrete);
    const vals = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs, vals);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .values = vals };
}
fn symbolicFault(a: std.mem.Allocator) !void {
    var owned = try symbolic(a);
    defer owned.deinit();
    try owned.evaluate();
}
test "RAM range forest: scalar symbolic original shard conservation parity" {
    var owned = try symbolic(std.testing.allocator);
    defer owned.deinit();
    // Provider exposes only its actual sum in this algebra. Its count is
    // separately checked through original LE2 byte reads in the real graph.
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 21, 22, 44, 48, 49, 65 }) |i| {
        const original = owned.inputs[i];
        owned.inputs[i] = original.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, owned.evaluate());
        owned.inputs[i] = original;
    }
    try owned.evaluate();
}
test "RAM range forest: every symbolic shard allocation failure releases ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, symbolicFault, .{});
}
test "RAM range forest: no external descendant supplier or complete block authority" {
    const Bus = @import("block_v5_ram_range_forest_bus_v1.zig");
    const Summary = @import("block_v5_ram_range_forest_summary_bus_v1.zig");
    const empty = try Bus.scheduleDigest(&.{});
    try std.testing.expectEqualSlices(u8, &empty, &(try Summary.scheduleDigest(&.{})));
    const wires = [_]Bus.Wire{.{ .circuit = 1, .wire = 1, .uses = 1, .kind = .child_cell, .coordinate = 0 }};
    try std.testing.expectError(error.ClosedRamRangeForestHasNoPublicTerms, Bus.scheduleDigest(&wires));
    try std.testing.expectError(error.ClosedRamRangeForestHasNoPublicTerms, Summary.Values.at(.{ .public = undefined }, wires[0]));
    try std.testing.expect(!Algebra.complete_block_authority and !Final.complete_block_authority);
    const P = @import("block_v5_ram_range_forest_protocol_v1.zig");
    try std.testing.expectEqualSlices(u8, &P.authorityUncached(), &P.sourceAuthority());
}
test "RAM range forest: actual original child node and final fresh producer bodies retained only" {
    const Providers = @import("block_v5_memory_recursive_provider_source_v1.zig");
    const B = @import("stwo_cpu_backend").CpuBackend;
    const Producer = @import("block_v5_ram_range_forest_producer_v1.zig").ForBackend(B);
    const FinalProducer = @import("block_v5_source_ram_forest_join_producer_v1.zig").ForBackend(B);
    inline for (.{ &Providers.ForKind(.ram).verify, &Providers.ForKind(.range).verify, &@import("block_v5_ram_range_forest_authority_v1.zig").Owned.init, &@import("block_v5_ram_range_forest_bus_v1.zig").Owner.prepareSources, &@import("block_v5_ram_range_forest_summary_receiver_v1.zig").verify, &@import("block_v5_ram_range_forest_source_v1.zig").Source.init, &@import("block_v5_ram_range_forest_preparation_v1.zig").prepare, &Producer.deriveGeometry, &Producer.init, &Producer.proveEncodedConsuming, &@import("block_v5_ram_range_forest_stage_v1.zig").ForBackend(B).publish, &@import("block_v5_source_ram_forest_join_public_v1.zig").Owner.init, &@import("block_v5_source_ram_forest_join_preparation_v1.zig").prepare, &@import("block_v5_source_ram_forest_join_receiver_v1.zig").verify, &FinalProducer.deriveKey, &FinalProducer.init, &FinalProducer.proveEncodedConsuming }) |function| {
        std.mem.doNotOptimizeAway(function);
        try std.testing.expect(@intFromPtr(function) != 0);
    }
}
fn geometry(template: [32]u8) Base.Key {
    return .{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
}
fn authority(a: std.mem.Allocator) !void {
    const Seal = @import("../prover/block_v5_source_seal_v1.zig");
    const A = @import("block_v5_ram_range_forest_authority_v1.zig");
    const Bus = @import("block_v5_ram_range_forest_bus_v1.zig");
    const Protocol = @import("block_v5_ram_range_forest_protocol_v1.zig");
    const LA = @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig");
    const RA = @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    const LB = @import("block_v5_ram_lanes_recursive_public_bus_v1.zig");
    const RB = @import("block_v5_range16_recursive_public_bus_v1.zig");
    const LP = @import("block_v5_reusable_ram_lanes_parent_protocol_v1.zig");
    const RP = @import("block_v5_reusable_range16_parent_protocol_v1.zig");
    const RangeNative = @import("../prover/block_v5_range16_proof_v1.zig");
    const lane = pin(0, 1, 4, 2);
    const roots = [_][2][32]u8{.{ @splat(51), @splat(52) }};
    const digest = try Plans.digest(a, &.{lane}, 4, &roots, .{});
    var original_plan = try Plans.rangePlan(a, &.{lane}, 4, .{});
    defer original_plan.deinit(a);
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
        try lane.entry(),
        .{ .family = .memory_range, .index = 0, .instance_id = RangeNative.instanceId(original_plan.digest, 0), .roots = roots[0] },
    };
    var counts: [Seal.family_count]u32 = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
    var source = (try admission()).source.pins;
    source.memory_plan_digest = digest;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = digest, .initial_source_plan_digest = try source.initial.digest(), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .expected_final_rw_root = source.expected_final_rw_root, .rw_endpoint_plan_digest = try source.digest(), .config = Base.PCS_CONFIG, .counts = counts };
    const sealed = try Seal.seal(pins, &entries);
    var la = try LA.Prepared.init(a, lane, sealed, pins, &entries, .{});
    defer la.deinit();
    var ra = try RA.Prepared.init(a, original_plan.shards[0], original_plan.digest, roots[0], sealed, pins, &entries, .{});
    defer ra.deinit();
    const sums = @import("../prover/block_v5_ram_lanes_interaction_v1.zig").Claim{ .event_count = 4, .transition_sum = scalar(1), .link_sum = Q.zero(), .initial_sum = scalar(9), .endpoint_sum = scalar(13), .endpoint_count = 1, .range_count = lane.request_count, .range_sums = @splat(scalar(17)) };
    const native = Lane.OpenReceipt{ .pin = lane, .sums = sums, .sealed_digest = sealed.digest };
    const range_native = RangeNative.OpenReceipt{ .shard = ra.shard, .roots = ra.roots, .sealed_digest = sealed.digest, .claim = .{ .count = lane.request_count, .sum = supply([_]Q{ sums.transition_sum, sums.link_sum, sums.initial_sum, sums.endpoint_sum, Q.one() } ++ sums.range_sums)[0] } };
    const lv = try LB.Values.fromLanes(&la, native);
    const rv = try RB.Values.fromRange(&ra, range_native);
    const lw = [_]LB.Wire{.{ .circuit = LB.PUBLIC_CIRCUIT, .wire = 0, .uses = 1, .source = .sealed, .coordinate = 0 }};
    const rw = [_]RB.Wire{.{ .circuit = RB.PUBLIC_CIRCUIT, .wire = 0, .uses = 1, .source = .sealed, .coordinate = 0 }};
    const lk = try LP.Key.fromGeometry(geometry(lv.template), &lw);
    const rk = try RP.Key.fromGeometry(geometry(rv.template), &rw);
    var owned = try A.Owned.init(a, .{ .seal = pins, .expected_seal_digest = sealed.digest, .first_round = &entries, .pins = &.{lane}, .range_roots = &roots, .expected_total_events = 4, .source = source }, sealed, &.{.{ .admitted = &la, .proposal = native, .key = lk, .expected_id = try lk.identity(), .schedule = &lw }}, &.{.{ .admitted = &ra, .proposal = range_native, .key = rk, .expected_id = try rk.identity(), .schedule = &rw }}, .{});
    defer owned.deinit();
    try owned.require(owned.identity);
    var specs = [_]Bus.Spec{.{ .geometry = geometry(@splat(31)), .expected_id = undefined }};
    const key = try Protocol.Key.fromGeometry(specs[0].geometry, &.{});
    specs[0].expected_id = try key.identity();
    const policy = Bus.Policy{ .forest = &owned, .expected_plan = owned.identity, .specs = &specs, .index = 0 };
    var public = try Bus.Owner.init(a, policy, .{});
    defer public.deinit();
    var graph = try @import("air/block_v5_ram_range_forest_graph_v1.zig").prepare(a, &public);
    defer graph.deinit();
    try graph.circuit.evaluateInto(graph.inputs, graph.values);
    var compact = try @import("block_v5_ram_range_forest_summary_bus_v1.zig").Owner.init(a, policy, .{});
    defer compact.deinit();
    try compact.validate();
    const saved = owned.summaries[0][0];
    owned.summaries[0][0] = saved.add(Q.one());
    if (owned.node(0, owned.identity)) |_| return error.TestExpectedError else |failure| {
        if (failure != error.MutatedRamRangeForestRecipe) return failure;
    }
    owned.summaries[0][0] = saved;
    const old_key = owned.ram[0].expected_id;
    owned.ram[0].expected_id[0] ^= 1;
    if (owned.node(0, owned.identity)) |_| return error.TestExpectedError else |failure| {
        if (failure != error.MutatedRamRangeForestRecipe) return failure;
    }
    owned.ram[0].expected_id = old_key;
    try policy.validate();
    var changed = policy;
    changed.expected_plan[0] ^= 1;
    if (changed.validate()) |_| return error.TestExpectedError else |failure| {
        if (failure != error.UntrustedRamRangeForestRoster) return failure;
    }
}
test "RAM range forest: original admissions graph and immutable local recipe identity" {
    try authority(std.testing.allocator);
}
test "RAM range forest: every original admission and node graph allocation failure releases owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, authority, .{});
}
