//! Nonproving algebra/original transcript fixtures. Literal claims and roots
//! below are proposals, never constructed Fresh/Verified or proof authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Algebra = @import("air/block_v5_memory_recursive_join_algebra_v1.zig");
const Forest = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
const OriginalJoin = @import("../prover/block_v5_memory_source_page_join_algebra_v1.zig");
const Batch = @import("../prover/block_v5_memory_source_batch_protocol_v1.zig");
const Auth = @import("../prover/block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("../prover/block_v5_initial_sources_v1.zig");
const Defaults = @import("../prover/block_v5_memory_source_batch_defaults_v1.zig");
const Range = @import("../prover/block_v5_range16_v1.zig");
const Interaction = @import("../prover/block_v5_ram_lanes_interaction_v1.zig");
const R = @import("air/composition_graph_recorder.zig");
const Providers = @import("block_v5_memory_recursive_provider_source_v1.zig");
const LaneNative = @import("../prover/block_v5_ram_lanes_proof_v1.zig");
const RangeNative = @import("../prover/block_v5_range16_proof_v1.zig");
const LaneAdmission = @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig");
const RangeAdmission = @import("../prover/block_v5_range16_recursive_admission_v1.zig");
const LaneBus = @import("block_v5_ram_lanes_recursive_public_bus_v1.zig");
const RangeBus = @import("block_v5_range16_recursive_public_bus_v1.zig");
const LaneProtocol = @import("block_v5_reusable_ram_lanes_parent_protocol_v1.zig");
const RangeProtocol = @import("block_v5_reusable_range16_parent_protocol_v1.zig");
const Seal = @import("../prover/block_v5_source_seal_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
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
fn laneClaims() Algebra.Lane(Q) {
    return .{ .event_count = Q.fromBase(M.fromCanonical(3)), .transition = scalar(19), .predecessor = Q.zero(), .initial = scalar(7).neg(), .endpoint = scalar(11), .endpoint_count = Q.zero(), .range_count = Q.fromBase(M.fromCanonical(38)), .ranges = @splat(scalar(23)) };
}
fn provider(lane: Algebra.Lane(Q)) Algebra.Provider(Q) {
    var sum = Q.zero();
    for (lane.ranges) |request| sum = sum.sub(request);
    return .{ .sum = sum, .count = lane.range_count };
}
fn shard(index: u32) Range.Shard {
    return .{ .index = index, .first_instance = index, .instance_count = 1, .request_count = 38 };
}
test "recursive memory join: exact original PAGE signs and open transition scalar parity" {
    const admitted = try admission();
    const source = sourceClaims();
    const lane = laneClaims();
    var sink = Sink{};
    const result = try Algebra.close(Q, &sink, &admitted, source, &.{lane}, &.{3}, &.{38});
    try std.testing.expect(result.eql(lane.transition));
    const decoded = Forest.decode(Q, source);
    var raw: Auth.Sums = undefined;
    inline for (std.meta.fields(Auth.Sums)) |field| @field(raw, field.name) = @field(decoded.source, field.name);
    try OriginalJoin.close(&admitted, .{ .raw = raw, .indexed = decoded.indexed, .fold = decoded.fold, .initial = lane.initial, .endpoint = lane.endpoint, .predecessor = lane.predecessor });
    try Algebra.rangeGroup(Q, &sink, shard(0), provider(lane), &.{lane});
    try std.testing.expect(!Algebra.complete_block_authority);
}
test "recursive memory join: every original source and RAM closed coordinate is mandatory" {
    const admitted = try admission();
    const source = sourceClaims();
    const lane = laneClaims();
    var sink = Sink{};
    for (0..Forest.CLAIM_COUNT) |index| {
        var changed = source;
        changed[index] = changed[index].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, &admitted, changed, &.{lane}, &.{3}, &.{38}));
    }
    inline for (.{ "event_count", "predecessor", "initial", "endpoint", "endpoint_count", "range_count" }) |field| {
        var changed = lane;
        @field(changed, field) = @field(changed, field).add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, &admitted, source, &.{changed}, &.{3}, &.{38}));
    }
    var open_changed = lane;
    open_changed.transition = open_changed.transition.add(Q.one());
    try std.testing.expect((try Algebra.close(Q, &sink, &admitted, source, &.{open_changed}, &.{3}, &.{38})).eql(open_changed.transition));
    try std.testing.expectError(error.UntrustedRecursiveMemoryCensus, Algebra.close(Q, &sink, &admitted, source, &.{lane}, &.{}, &.{38}));
    try std.testing.expectError(error.RecursiveMemoryFieldCensusOverflow, Algebra.base(Q, core.fields.m31.Modulus));
}
test "recursive memory join: range planes and per-shard deficits cannot pool or cancel" {
    const lane = laneClaims();
    const supply = provider(lane);
    var sink = Sink{};
    for (0..Interaction.RANGE_PLANES) |index| {
        var changed = lane;
        changed.ranges[index] = changed.ranges[index].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.rangeGroup(Q, &sink, shard(0), supply, &.{changed}));
    }
    var deficit = supply;
    deficit.sum = deficit.sum.add(Q.one());
    var excess = supply;
    excess.sum = excess.sum.sub(Q.one());
    try std.testing.expect(deficit.sum.add(excess.sum).eql(supply.sum.add(supply.sum)));
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.rangeGroup(Q, &sink, shard(0), deficit, &.{lane}));
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.rangeGroup(Q, &sink, shard(1), excess, &.{lane}));
    deficit = supply;
    deficit.count = deficit.count.add(Q.one());
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.rangeGroup(Q, &sink, shard(0), deficit, &.{lane}));
    var wrong_shard = shard(0);
    wrong_shard.request_count += 1;
    try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.rangeGroup(Q, &sink, wrong_shard, supply, &.{lane}));
    try std.testing.expectError(error.UntrustedRecursiveMemoryRangeGroup, Algebra.rangeGroup(Q, &sink, shard(0), supply, &.{}));
}
test "recursive memory join: zero RAM still closes source roots and rejects residual endpoints" {
    const admitted = try admission();
    var source: [Forest.CLAIM_COUNT]Q = @splat(Q.zero());
    source[21] = Q.one();
    var sink = Sink{};
    try std.testing.expect((try Algebra.close(Q, &sink, &admitted, source, &.{}, &.{}, &.{})).isZero());
    for ([_]usize{ 6, 7, 21 }) |index| {
        var changed = source;
        changed[index] = changed[index].add(Q.one());
        try std.testing.expectError(error.UnclosedRecursiveMemoryFixture, Algebra.close(Q, &sink, &admitted, changed, &.{}, &.{}, &.{}));
    }
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
fn equation(a: std.mem.Allocator) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const source = sourceClaims();
    const lane = laneClaims();
    const supply = provider(lane);
    const concrete = source ++ [_]Q{ lane.event_count, lane.transition, lane.predecessor, lane.initial, lane.endpoint, lane.endpoint_count, lane.range_count } ++ lane.ranges ++ [_]Q{ supply.sum, supply.count, lane.transition };
    var symbols: [concrete.len]R.Scalar = undefined;
    for (&symbols) |*symbol| symbol.* = (try builder.input()).value;
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    var sink = SymbolicSink{ .builder = &builder };
    const symbolic_lane = Algebra.Lane(R.Scalar){ .event_count = symbols[22], .transition = symbols[23], .predecessor = symbols[24], .initial = symbols[25], .endpoint = symbols[26], .endpoint_count = symbols[27], .range_count = symbols[28], .ranges = symbols[29..46].* };
    const admitted = try admission();
    const transition = try Algebra.close(R.Scalar, &sink, &admitted, symbols[0..22].*, &.{symbolic_lane}, &.{3}, &.{38});
    try Algebra.rangeGroup(R.Scalar, &sink, shard(0), .{ .sum = symbols[46], .count = symbols[47] }, &.{symbolic_lane});
    try sink.zero(transition.sub(symbols[48]));
    try builder.check();
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try temp.dupe(Q, &concrete);
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .values = values };
}
fn equationAllocation(a: std.mem.Allocator) !void {
    var owned = try equation(a);
    defer owned.deinit();
    try owned.evaluate();
}
test "recursive memory join: original scalar symbolic equations bind all49 routed inputs" {
    var owned = try equation(std.testing.allocator);
    defer owned.deinit();
    for (owned.inputs) |*value| {
        const old = value.*;
        value.* = old.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, owned.evaluate());
        value.* = old;
        try owned.evaluate();
    }
}
test "recursive memory join: every symbolic equation allocation failure releases owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationAllocation, .{});
}

const Metadata = struct {
    lane: LaneNative.Pin,
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init() !@This() {
        var self: @This() = undefined;
        const Event = @import("../air/block/memory_transition.zig").Transition;
        const first = Event{ .space = 1, .address = 0x8000_0000, .clock = (@as(u64, 1) << 40) + 1, .before = 7, .after = 8 };
        var last = first;
        last.clock += 2;
        last.before += 2;
        last.after += 2;
        self.lane = .{ .claim = .{ .first_event = 0, .total_events = 3, .events = 3, .row_log = 2, .first = first, .last = last, .preceding = null }, .index = 0, .roots = .{ @splat(8), @splat(9) }, .request_count = 38, .counter_digest = @splat(10), .config = Base.PCS_CONFIG };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            try self.lane.entry(),
            .{ .family = .memory_range, .index = 0, .instance_id = RangeNative.instanceId(@splat(6), 0), .roots = .{ @splat(51), @splat(52) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .config = Base.PCS_CONFIG, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        return self;
    }
    fn sums(self: *const @This()) Interaction.Claim {
        return .{ .event_count = 3, .transition_sum = scalar(1), .link_sum = scalar(5), .initial_sum = scalar(9), .endpoint_sum = scalar(13), .endpoint_count = 1, .range_count = self.lane.request_count, .range_sums = @splat(scalar(17)) };
    }
};
fn geometry(template: [32]u8) Base.Key {
    return .{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
}
fn readWord(bytes: [4]M) u32 {
    var value: u32 = 0;
    for (bytes, 0..) |byte, index| value |= byte.v << @as(u5, @intCast(8 * index));
    return value;
}
fn normalizers(a: std.mem.Allocator) !void {
    const fixture = try Metadata.init();
    var lane = try LaneAdmission.Prepared.init(a, fixture.lane, fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer lane.deinit();
    const lane_values = try LaneBus.Values.fromLanes(&lane, .{ .pin = lane.pin, .sums = fixture.sums(), .sealed_digest = fixture.sealed.digest });
    const lane_wires = [_]LaneBus.Wire{.{ .circuit = LaneBus.PUBLIC_CIRCUIT, .wire = 0, .uses = 1, .source = .sealed, .coordinate = 0 }};
    const lane_key = try LaneProtocol.Key.fromGeometry(geometry(lane_values.template), &lane_wires);
    const lane_authority = try LaneProtocol.Admission.init(lane_key, try lane_key.identity(), &lane_wires, lane_values);
    var lane_normal = try Providers.ForKind(.ram).Normalized.init(a, &lane_authority, .{});
    defer lane_normal.deinit();
    try lane_normal.require(a, &lane_authority, .{});
    for (lane_values.claimWords(), 0..) |value, index| try std.testing.expectEqual(value, readWord(try lane_normal.cell(lane_normal.count_first + @as(u32, @intCast(index)))));
    var changed = lane_normal;
    changed.count_first += 1;
    if (changed.require(a, &lane_authority, .{})) |_| return error.TestExpectedError else |failure| {
        // Fault sweeps must propagate genuine allocation failure from the
        // independent reconstruction, rather than hide it in expectError.
        if (failure != error.MutatedRecursiveMemorySource) return failure;
    }
    var provider_admitted = try RangeAdmission.Prepared.init(a, shard(0), @splat(6), fixture.entries[5].roots, fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer provider_admitted.deinit();
    const range_values = try RangeBus.Values.fromRange(&provider_admitted, .{ .shard = provider_admitted.shard, .roots = provider_admitted.roots, .sealed_digest = fixture.sealed.digest, .claim = .{ .sum = scalar(41), .count = 38 } });
    const range_wires = [_]RangeBus.Wire{.{ .circuit = RangeBus.PUBLIC_CIRCUIT, .wire = 0, .uses = 1, .source = .sealed, .coordinate = 0 }};
    const range_key = try RangeProtocol.Key.fromGeometry(geometry(range_values.template), &range_wires);
    const range_authority = try RangeProtocol.Admission.init(range_key, try range_key.identity(), &range_wires, range_values);
    var range_normal = try Providers.ForKind(.range).Normalized.init(a, &range_authority, .{});
    defer range_normal.deinit();
    try range_normal.require(a, &range_authority, .{});
    try std.testing.expectEqual(@as(u32, 38), readWord(try range_normal.cell(range_normal.count_first)));
    try std.testing.expectEqual(@as(u32, 0), readWord(try range_normal.cell(range_normal.count_first + 1)));
    for (range_values.sum.toM31Array(), 0..) |limb, index| try std.testing.expectEqual(limb.v, readWord(try range_normal.cell(range_normal.sum_first + @as(u32, @intCast(index)))));
}
test "recursive memory join: original RAM90 and range count secure transcript coordinates" {
    try normalizers(std.testing.allocator);
}
test "recursive memory join: transcript allocation failures preserve independent original admissions" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, normalizers, .{});
}
test "recursive memory join: resource rejection precedes any original child capture or proof" {
    const Public = @import("block_v5_memory_recursive_join_public_v1.zig");
    const Prepare = @import("block_v5_memory_recursive_join_preparation_v1.zig");
    const Receive = @import("block_v5_memory_recursive_join_receiver_v1.zig");
    try std.testing.expectError(error.RecursiveMemoryJoinResourceLimit, Public.init(std.testing.allocator, .{ .source = undefined, .memory = undefined, .ram = &.{}, .range = &.{} }, .{ .max_children = 0 }));
    const too_many: [Public.MAX_CHILD_VERIFIERS]*const Providers.ForKind(.ram).Fresh = undefined;
    // Four RAM children plus the mandatory PAGE root exceeds strict fan-in;
    // increasing a caller-configured budget must not bypass the protocol cap.
    try std.testing.expectError(error.RecursiveMemoryJoinResourceLimit, Public.init(std.testing.allocator, .{ .source = undefined, .memory = undefined, .ram = &too_many, .range = &.{} }, .{ .max_children = 8193 }));
    try std.testing.expectError(error.RecursiveMemoryJoinResourceLimit, Prepare.prepare(std.testing.allocator, undefined, 0, .{}));
    try std.testing.expectError(error.WidePublicResourceLimit, Receive.verify(std.testing.allocator, .{ .public = undefined, .key = undefined, .expected_id = undefined, .schedule = &.{}, .max_proof_bytes = 0 }, &.{}));
    try std.testing.expect(!Receive.Fresh.complete_block_authority);
}
test "recursive memory join: actual original leaf same parent prepare and fresh receiver bodies retained only" {
    const Public = @import("block_v5_memory_recursive_join_public_v1.zig");
    const Producer = @import("block_v5_memory_recursive_join_producer_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    inline for (.{ &Providers.ForKind(.ram).verify, &Providers.ForKind(.range).verify, &Providers.ForKind(.ram).Fresh.validate, &Providers.ForKind(.range).Fresh.validate, &Public.Owner.init, &Public.Owner.validate, &@import("air/block_v5_memory_recursive_join_graph_v1.zig").prepare, &@import("block_v5_memory_recursive_join_preparation_v1.zig").prepare, &@import("block_v5_memory_recursive_join_receiver_v1.zig").verify, &Producer.deriveKey, &Producer.init, &Producer.proveEncodedConsuming }) |function| {
        std.mem.doNotOptimizeAway(function);
        try std.testing.expect(@intFromPtr(function) != 0);
    }
}
