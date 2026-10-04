//! Nonproving lifecycle custody/transport/API fixtures. Physical first-round
//! commitments are permitted; no test invokes a STARK, FRI or guest run.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Protocol = @import("../block_v5_ram_lanes_protocol_v1.zig");
const Trace = @import("../../air/block/word_memory_lanes_trace_v1.zig");
const Proof = @import("../block_v5_ram_lanes_proof_v1.zig");
const Stage = @import("../block_v5_ram_lanes_stage_v1.zig");
const Plan = @import("../block_v5_ram_lanes_plan_v1.zig");
const Receiver = @import("../block_v5_ram_lanes_receiver_v1.zig");
const Artifact = @import("../block_v5_ram_lanes_artifact_v1.zig");
const Interaction = @import("../block_v5_ram_lanes_interaction_v1.zig");
const Range = @import("../block_v5_range16_v1.zig");
const Join = @import("../block_v5_ram_lanes_join_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Wire = @import("../guest_precompile/proof_artifact_wire.zig");
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
}
fn event(index: u32) Event {
    return .{ .space = 1, .address = 0x2000, .clock = @as(u64, index) + 1, .before = index, .after = index + 1 };
}
fn claim() Protocol.Claim {
    return .{ .first_event = 0, .total_events = 3, .events = 3, .row_log = 2, .first = event(0), .last = event(2), .preceding = null };
}
fn pin() !Proof.Pin {
    return .{ .claim = claim(), .index = 0, .roots = .{ @splat(7), @splat(8) }, .request_count = 38, .counter_digest = @splat(9), .config = try config() };
}
fn sums() Interaction.Claim {
    return .{ .event_count = 3, .transition_sum = Q.fromU32Unchecked(3, 5, 7, 11), .link_sum = Q.zero(), .initial_sum = Q.one(), .endpoint_sum = Q.one(), .endpoint_count = 1, .range_count = 38, .range_sums = @splat(Q.one()) };
}
const FixtureSeal = struct { pins: Seal.Pins, entries: [6]Seal.Entry, sealed: Seal.Sealed };
fn fixtureSeal(memory_pin: Proof.Pin, memory_digest: [32]u8, range_digest: [32]u8) !FixtureSeal {
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family|
        counts[@intFromEnum(family) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = memory_digest, .initial_source_plan_digest = @splat(25), .expected_final_rw_root = @splat(26), .rw_endpoint_plan_digest = @splat(27), .register_endpoint_plan_digest = @splat(28), .register_custody_mode = 1, .config = memory_pin.config, .counts = counts };
    const entries = [6]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        try memory_pin.entry(),
        .{ .family = .memory_range, .index = 0, .instance_id = @import("../block_v5_range16_proof_v1.zig").instanceId(range_digest, 0), .roots = .{ @splat(22), @splat(23) } },
    };
    return .{ .pins = pins, .entries = entries, .sealed = try Seal.seal(pins, &entries) };
}

test "block-v5 ram lifecycle physical warm roots counters fixed reconstruction and phase custody" {
    const a = std.testing.allocator;
    var trace = try Trace.Trace.init(a, claim(), .{ .max_row_log = 4, .max_events = 16, .max_owned_bytes = 1 << 20 });
    defer trace.deinit();
    for (0..3) |index| try trace.append(event(@intCast(index)));
    try trace.seal();
    var trusted = try Trace.FixedTrace.init(a, trace.claim, 1 << 20);
    defer trusted.deinit();
    for (0..Protocol.FIXED_COLUMNS) |index| try std.testing.expectEqualSlices(core.fields.m31.M31, trace.fixedColumn(index), trusted.column(index));
    var local = try Range.Counter.init(a);
    defer local.deinit();
    var first = try Proof.ForBackend(Cpu).commitFirstRoundWithCounter(a, &trace, 0, try config(), true, .{}, &local);
    defer first.deinit(a);
    try first.require(a, &trace, first.pin);
    try std.testing.expectEqual(@as(u64, 38), first.pin.request_count);
    try std.testing.expectEqualDeep(local.digest(), first.pin.counter_digest);
    try std.testing.expectEqual(@as(usize, 2), first.pcs_first.scheme.trees.items.len);
    // The committed domains are rowlog2, not the virtual eventlog3.
    for (first.pcs_first.scheme.trees.items) |tree| {
        for (tree.coefficients.?) |poly| try std.testing.expectEqual(@as(u32, 2), poly.logSize());
        for (tree.columns) |column| try std.testing.expectEqual(@as(u32, 3), column.log_size); // row2 + blowup1
    }
    var wrong = first.pin;
    wrong.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesWarmFirst, first.require(a, &trace, wrong));
    wrong = first.pin;
    wrong.counter_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesWarmFirst, first.require(a, &trace, wrong));
    wrong = first.pin;
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedV5RamLanesWarmFirst, first.require(a, &trace, wrong));
    first.pcs_first.owns_scheme = false;
    try std.testing.expectError(error.UntrustedV5RamLanesWarmFirst, first.require(a, &trace, first.pin));
    first.pcs_first.owns_scheme = true;
    first.pcs_first.scheme.setCoefficientRetentionPolicy(.never);
    try std.testing.expectError(error.UntrustedV5RamLanesWarmFirst, first.require(a, &trace, first.pin));
    first.pcs_first.scheme.setCoefficientRetentionPolicy(.always);
    try std.testing.expectError(error.V5RamLanesResourceLimit, Trace.FixedTrace.init(a, claim(), 1));
    var counted = try Range.Counter.init(a);
    defer counted.deinit();
    _ = try Proof.collectCounter(&trace, &counted);
    try std.testing.expectEqualDeep(local.digest(), counted.digest());
}

test "block-v5 ram lifecycle seal roots row frame counters transcript and v4 relabel swaps reject" {
    const a = std.testing.allocator;
    const p = try pin();
    var range_plan = try Plan.rangePlan(a, &.{p}, 3, .{});
    defer range_plan.deinit(a);
    const range_roots = [_][2][32]u8{.{ @splat(22), @splat(23) }};
    const digest = try Plan.digest(a, &.{p}, 3, &range_roots, .{});
    const fixture = try fixtureSeal(p, digest, range_plan.digest);
    try Proof.admit(p, fixture.sealed, fixture.pins, &fixture.entries);
    const value = sums();
    const channel = try Proof.proofChannel(a, fixture.sealed, p, value);
    var replay = fixture.sealed.sharedChannel();
    _ = try Protocol.Challenges.drawFromChannel(a, &replay);
    replay.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x50524f46 });
    replay.mixRoot(Protocol.abiId());
    replay.mixRoot(try p.identity());
    Proof.mixClaims(&replay, value);
    try std.testing.expectEqualDeep(channel.digestBytes(), replay.digestBytes());
    var wrong = p;
    wrong.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, Proof.admit(wrong, fixture.sealed, fixture.pins, &fixture.entries));
    wrong = p;
    wrong.claim.row_log = 3;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, Proof.admit(wrong, fixture.sealed, fixture.pins, &fixture.entries));
    try std.testing.expect(!std.meta.eql(Proof.firstChannel(p.claim, p.index, p.config).digestBytes(), Proof.firstChannel(wrong.claim, p.index, p.config).digestBytes()));
    wrong = p;
    wrong.counter_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, Proof.admit(wrong, fixture.sealed, fixture.pins, &fixture.entries));
    var old = fixture.entries;
    old[4].instance_id = @import("../block_v5_word_memory_proof_v1.zig").instanceId(p.claim.legacy(), 0);
    const old_seal = try Seal.seal(fixture.pins, &old);
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, Proof.admit(p, old_seal, fixture.pins, &old));
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, Proof.admit(p, old_seal, fixture.pins, &old));
    var stale = fixture.sealed;
    stale.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, Proof.admit(p, stale, fixture.pins, &fixture.entries));
    var altered = value;
    altered.range_sums[0] = altered.range_sums[0].add(Q.one());
    try std.testing.expect(!std.meta.eql(channel.digestBytes(), (try Proof.proofChannel(a, fixture.sealed, p, altered)).digestBytes()));
    const buses = Join.buses(value);
    try std.testing.expectEqualDeep(value.transition_sum, buses.transition_sum);
    try std.testing.expectEqualDeep(Q.fromBase(core.fields.m31.M31.fromCanonical(17)), buses.rangeSum());
    try std.testing.expect(buses.registerEndpointSum().isZero());
    try std.testing.expectEqual(@as(u64, 0), buses.registerEndpointCount());
    // Root/census/plan admission alone is not source/proof authority. The
    // receiver's later verify() must authenticate the real endpoint files.
    var source = std.mem.zeroes(@import("../block_v5_rw_endpoint_sources_v1.zig").Pins);
    source.memory_plan_digest = digest;
    source.expected_final_rw_root = fixture.pins.expected_final_rw_root;
    const pins = Receiver.Pins{ .seal = fixture.pins, .expected_seal_digest = fixture.sealed.digest, .first_round = &fixture.entries, .pins = &.{p}, .range_roots = &range_roots, .expected_total_events = 3, .source = source };
    try Receiver.admit(a, pins, fixture.sealed, pins.limits);
    var wrong_receiver = pins;
    wrong_receiver.source.memory_plan_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesPlan, Receiver.admit(a, wrong_receiver, fixture.sealed, pins.limits));
    wrong_receiver = pins;
    wrong_receiver.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesReceiver, Receiver.admit(a, wrong_receiver, fixture.sealed, pins.limits));
    wrong_receiver = pins;
    wrong_receiver.limits.proof.max_row_log += 1;
    try std.testing.expectError(error.UntrustedV5RamLanesReceiverLimits, Receiver.admit(a, wrong_receiver, fixture.sealed, pins.limits));
}

test "block-v5 ram lifecycle independently plans field safe shards bounds and typed empty roster" {
    const a = std.testing.allocator;
    const count: u32 = 1 << 25;
    var pins: [5]Proof.Pin = undefined;
    for (&pins, 0..) |*out, index| {
        const start = @as(u64, count) * index;
        const first = Event{ .space = 1, .address = 0x2000, .clock = start + 1, .before = 0, .after = 0 };
        out.* = .{ .claim = .{ .first_event = start, .total_events = @as(u64, count) * pins.len, .events = count, .row_log = 24, .first = first, .last = .{ .space = 1, .address = first.address, .clock = start + count, .before = 0, .after = 0 }, .preceding = if (index == 0) null else pins[index - 1].claim.last }, .index = @intCast(index), .request_count = 14 * @as(u64, count) - (if (index == 0) @as(u64, 4) else 0), .counter_digest = @splat(@intCast(index + 1)), .roots = .{ @splat(7), @splat(8) }, .config = try config() };
    }
    var plan = try Plan.rangePlan(a, &pins, @as(u64, count) * pins.len, .{});
    defer plan.deinit(a);
    try Plan.admit(a, &plan, &pins, plan.total_events, .{});
    try std.testing.expectEqual(@as(usize, 2), plan.shards.len);
    try std.testing.expectEqual(@as(u32, 4), plan.shards[0].instance_count);
    plan.shards[0].instance_count -= 1;
    try std.testing.expectError(error.InvalidV5RamLanesRangeRoster, Plan.admit(a, &plan, &pins, plan.total_events, .{}));
    plan.shards[0].instance_count += 1;
    try std.testing.expectError(error.V5RamLanesResourceLimit, Plan.rangePlan(a, &pins, plan.total_events, .{ .max_shards = 1 }));
    var no_storage: [0]u8 = .{};
    var no_alloc = std.heap.FixedBufferAllocator.init(&no_storage);
    // This cap must reject before temporary claims or the provider vector can
    // allocate; OutOfMemory would expose a late resource admission regression.
    try std.testing.expectError(error.V5RamLanesResourceLimit, Plan.rangePlan(no_alloc.allocator(), &pins, plan.total_events, .{ .max_shards = 1 }));
    try std.testing.expectError(error.V5RamLanesResourceLimit, Plan.rangePlan(a, &pins, plan.total_events, .{ .max_metadata_bytes = 1 }));
    var reordered = pins;
    std.mem.swap(Proof.Pin, &reordered[0], &reordered[1]);
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Plan.rangePlan(a, &reordered, plan.total_events, .{}));
    const roots = [_][2][32]u8{ .{ @splat(11), @splat(12) }, .{ @splat(13), @splat(14) } };
    const digest = try Plan.digest(a, &pins, plan.total_events, &roots, .{});
    var changed = pins;
    changed[0].counter_digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(digest, try Plan.digest(a, &changed, plan.total_events, &roots, .{})));
    var empty = try Stage.ForBackend(Cpu).collectEmpty(a, try config(), .{});
    defer empty.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), empty.pins.len);
    try std.testing.expectEqual(@as(usize, 0), empty.plan.shards.len);
    try std.testing.expectEqualDeep(try Plan.digest(a, &.{}, 0, &.{}, .{}), empty.plan_digest);
    try std.testing.expect(!std.meta.eql(empty.plan_digest, @import("../block_v5_empty_rw_memory_v1.zig").planDigest()));
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Plan.rangePlan(a, &.{}, 1, .{}));
}

fn envelopeBytes(a: std.mem.Allocator, expected: Artifact.Expected, value: Interaction.Claim) ![]u8 {
    // Deliberately invalid STARK payload. Envelope admission proves no AIR;
    // the real strict decoder below must reject it before proof allocations.
    const raw = try a.alloc(u8, Artifact.HEADER_BYTES + 1);
    errdefer a.free(raw);
    var writer = std.Io.Writer.fixed(raw);
    try writer.writeAll(Artifact.MAGIC);
    try writer.writeAll(&Protocol.abiId());
    try writer.writeAll(&try expected.identity());
    try writer.writeAll(&expected.expected_seal_digest);
    try writer.writeAll(&try Proof.instanceId(expected.pin));
    try Wire.writeInt(&writer, u32, expected.pin.index);
    try Wire.writeInt(&writer, u64, 1);
    try Artifact.writeClaims(&writer, value);
    try writer.writeByte(0xff);
    try std.testing.expectEqual(raw.len, writer.buffered().len);
    return raw;
}
test "block-v5 ram lifecycle artifact canonical claim envelope rejects stale policy ABI census and invalid STARK" {
    const a = std.testing.allocator;
    const expected = Artifact.Expected{ .pin = try pin(), .expected_seal_digest = @splat(19) };
    const value = sums();
    const raw = try envelopeBytes(a, expected, value);
    defer a.free(raw);
    const admitted = try Artifact.envelope(raw, expected, .{});
    try std.testing.expectEqualDeep(value, admitted.claim);
    try std.testing.expectEqualSlices(u8, &.{0xff}, admitted.proof_bytes);
    if (Artifact.decode(a, raw, expected, .{})) |decoded| {
        var proof = decoded;
        proof.deinit(a);
        return error.AcceptedInvalidRamProof;
    } else |_| {}
    var changed = expected;
    changed.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.envelope(raw, changed, .{}));
    changed = expected;
    changed.pin.index = 1;
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.envelope(raw, changed, .{}));
    changed = expected;
    changed.pin.claim.row_log += 1;
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.envelope(raw, changed, .{}));
    const saved = raw[Artifact.MAGIC.len];
    raw[Artifact.MAGIC.len] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.envelope(raw, expected, .{}));
    raw[Artifact.MAGIC.len] = saved;
    try std.testing.expectError(error.V5RamLanesArtifactResourceLimit, Artifact.envelope(raw, expected, .{ .artifact_bytes = Artifact.HEADER_BYTES }));
    var wrong_count = value;
    wrong_count.event_count += 1;
    const wrong = try envelopeBytes(a, expected, wrong_count);
    defer a.free(wrong);
    try std.testing.expectError(error.InvalidV5RamLanesInteractionCensus, Artifact.envelope(wrong, expected, .{}));
    const legacy = @import("../block_v5_word_memory_protocol_v1.zig").abiId();
    @memcpy(raw[Artifact.MAGIC.len..][0..32], &legacy);
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.envelope(raw, expected, .{}));
}

test "block-v5 ram lifecycle concrete production proof receiver codec stage APIs codegen" {
    const Api = Proof.ForBackend(Cpu);
    const Staged = Stage.ForBackend(Cpu);
    const prepared: *const @TypeOf(Api.provePrepared) = &Api.provePrepared;
    const verify: *const @TypeOf(Api.verifyOwned) = &Api.verifyOwned;
    const staged: *const @TypeOf(Staged.proveWithBoundary) = &Staged.proveWithBoundary;
    const collect: *const @TypeOf(Staged.collect) = &Staged.collect;
    const encode: *const @TypeOf(Artifact.encode) = &Artifact.encode;
    const decode: *const @TypeOf(Artifact.decode) = &Artifact.decode;
    const put: *const @TypeOf(Artifact.put) = &Artifact.put;
    const load: *const @TypeOf(Artifact.load) = &Artifact.load;
    const receiver: *const @TypeOf(receiverBody) = &receiverBody;
    inline for (.{ prepared, verify, staged, collect, encode, decode, put, load, receiver }) |function| std.mem.doNotOptimizeAway(function);
}
test "block-v5 ram lifecycle physical FRI and allocation guards precede caller selected bytes" {
    const p = try pin();
    var expected = Artifact.Expected{ .pin = p, .expected_seal_digest = @splat(19) };
    const original_shape = try Artifact.preflightShape(expected, .{});
    // Optional config lifting is compared and transcript-bound, but this
    // family's actual final composition and sampled columns remain rowlog2.
    expected.pin.config.lifting_log_size = 30;
    const shape = try Artifact.preflightShape(expected, .{});
    try std.testing.expectEqual(@as(u32, 2), shape.max_column_log_size);
    try std.testing.expectEqual(@as(u32, 2), shape.max_merkle_column_log_size);
    try std.testing.expectEqual(@as(?u32, 30), shape.config.lifting_log_size);
    try std.testing.expectEqualDeep(original_shape.tree_columns, shape.tree_columns);
    try std.testing.expectEqualDeep([_]u32{ 24, 54, 92, 16 }, shape.tree_columns);
    try std.testing.expectEqualDeep([_]u32{ 1, 2, 2, 1 }, shape.sample_width_limits);
    try std.testing.expect(!std.meta.eql(try p.identity(), try expected.pin.identity()));
    var no_storage: [0]u8 = .{};
    var no_alloc = std.heap.FixedBufferAllocator.init(&no_storage);
    expected.pin.config.fri_config.fold_step = 3;
    try std.testing.expectError(error.InvalidV5RamLanesPcsGeometry, Artifact.decode(no_alloc.allocator(), &.{}, expected, .{}));
    expected.pin = p;
    expected.pin.config.fri_config.log_last_layer_degree_bound = 2;
    try std.testing.expectError(error.InvalidV5RamLanesPcsGeometry, Artifact.decode(no_alloc.allocator(), &.{}, expected, .{}));
    expected.pin = p;
    expected.pin.claim.row_log = 24;
    expected.pin.config.fri_config.log_blowup_factor = 7;
    try std.testing.expectError(error.InvalidV5RamLanesPcsGeometry, Artifact.decode(no_alloc.allocator(), &.{}, expected, .{ .max_row_log = 24 }));
    try std.testing.expectError(error.V5RamLanesResourceLimit, (Proof.Limits{ .max_fixed_bytes = 1 }).require(p.claim));
    try std.testing.expectError(error.V5RamLanesResourceLimit, (Proof.Limits{ .max_interaction_bytes = Interaction.SCRATCH_BYTES }).require(p.claim));
}

const EmptySources = struct {
    spool: *@import("../../air/block/memory_spool.zig").Spool,
    loads: u32 = 0,
    fn open(raw: *anyopaque) anyerror!@import("../../air/block/memory_transition.zig").Reader {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return .{ .sorted = try self.spool.reopenSorted(), .initial = .{ .context = self, .load = initial } };
    }
    fn initial(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
        return error.UnexpectedEmptyRamInitialLoad;
    }
    fn memory(raw: *anyopaque, _: u32) anyerror!Proof.Proof {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.loads += 1;
        return error.UnexpectedEmptyRamProof;
    }
    fn range(raw: *anyopaque, _: u32) anyerror!@import("../block_v5_range16_proof_v1.zig").Proof {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.loads += 1;
        return error.UnexpectedEmptyRamProof;
    }
};
test "block-v5 ram lifecycle empty receiver authenticates untouched image and input without proof loaders" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try @import("../../air/block/memory_spool.zig").Spool.init(a, tmp.dir, 8);
    defer spool.deinit();
    var sorted = try spool.finishEmpty();
    sorted.deinit();
    var source = EmptySources{ .spool = &spool };
    const Tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
    const Writer = @import("../block_v5_memory_source_writer_v1.zig");
    const input = [_]u8{ 7, 0, 0, 0 };
    const hasher = Tree.TreeHasher.init(.memory);
    const root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 9 }, .{ .index = 0x3000 / 4, .value = 7 } })).bytes;
    const words = [_]@import("../block_memory_replay.zig").InitialWord{.{ .address = 0x2000, .value = 9, .source = .rw_root }};
    var files = try Writer.write(tmp.dir, .{
        .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = 0x2000, .data_end = 0x2800, .stack_bottom = 0x4000, .stack_top = 0x5000, .io_base = 0x3000, .io_end = 0x3800, .input_base = 0x3000, .input_end = 0x3100, .output_len_addr = 0x3200, .output_data_addr = 0x3204, .output_base = 0x3200, .output_end = 0x3800 },
        .initial_words = &words,
        .public_input = &input,
        .initial_registers = @splat(0),
        .expected_final_registers = @splat(0),
        .expected_initial_rw_root = root,
        .expected_final_rw_root = root,
        .expected_total_events = 0,
        .register_custody_mode = 1,
        .register_window_plan_digest = @splat(28),
    }, .{ .context = &source, .open = EmptySources.open });
    defer files.deinit();
    const digest = try Plan.digest(a, &.{}, 0, &.{}, .{});
    var endpoint = files.endpointPins(digest);
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request }) |family| counts[@intFromEnum(family) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = digest, .initial_source_plan_digest = try endpoint.initial.digest(), .expected_final_rw_root = root, .rw_endpoint_plan_digest = try endpoint.digest(), .register_endpoint_plan_digest = @splat(28), .register_custody_mode = 1, .config = try config(), .counts = counts };
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
    };
    var sealed = try Seal.seal(pins, &entries);
    var receiver = Receiver.Pins{ .seal = pins, .expected_seal_digest = sealed.digest, .first_round = &entries, .pins = &.{}, .range_roots = &.{}, .expected_total_events = 0, .source = endpoint };
    const loader = Receiver.Loader{ .context = &source, .take_memory = EmptySources.memory, .take_range = EmptySources.range };
    const scoped = try Receiver.verify(Cpu, a, receiver, &input, files.files(), loader, sealed, receiver.limits);
    try std.testing.expect(scoped.transition_sum.isZero());
    try std.testing.expectEqual(@as(u32, 0), scoped.memory_instances);
    try std.testing.expectEqualDeep(root, scoped.initial_rw_root);
    try std.testing.expectEqualDeep(root, scoped.final_rw_root);
    try std.testing.expectEqual(@as(u32, 0), source.loads);
    // The policy itself is resealed to the wrong independently supplied final
    // root. Digest-consistent metadata must still fail real source custody.
    endpoint.expected_final_rw_root[0] ^= 1;
    pins.expected_final_rw_root = endpoint.expected_final_rw_root;
    pins.rw_endpoint_plan_digest = try endpoint.digest();
    sealed = try Seal.seal(pins, &entries);
    receiver.seal = pins;
    receiver.expected_seal_digest = sealed.digest;
    receiver.source = endpoint;
    try std.testing.expectError(error.InvalidV5FinalRwRoot, Receiver.verify(Cpu, a, receiver, &input, files.files(), loader, sealed, receiver.limits));
    try std.testing.expectEqual(@as(u32, 0), source.loads);
    endpoint.expected_final_rw_root = root;
    pins.expected_final_rw_root = root;
    pins.rw_endpoint_plan_digest = try endpoint.digest();
    sealed = try Seal.seal(pins, &entries);
    receiver.seal = pins;
    receiver.expected_seal_digest = sealed.digest;
    receiver.source = endpoint;
    // Untouched leaves cannot be omitted or changed under an empty claim.
    try files.opened[1].pwriteAll(&.{10}, 4);
    try std.testing.expectError(error.UntrustedV5InitialSourceBytes, Receiver.verify(Cpu, a, receiver, &input, files.files(), loader, sealed, receiver.limits));
    try std.testing.expectEqual(@as(u32, 0), source.loads);
}
fn receiverBody(a: std.mem.Allocator, pins: Receiver.Pins, input: []const u8, files: @import("../block_v5_rw_endpoint_sources_v1.zig").Sources, loader: Receiver.Loader, sealed: Seal.Sealed) !Receiver.Scoped {
    return Receiver.verify(Cpu, a, pins, input, files, loader, sealed, pins.limits);
}
