//! Pure original-byte/framing/routing oracles. Metadata proposals below never
//! enter production admission/derive, a proof receiver or successful capture.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Raw = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const RawSchema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Frames = @import("../recursion/air/block_v5_recursive_statement_frames_v1.zig");
const Prefix = @import("../recursion/air/block_v5_memory_source_page_prefix_v1.zig");
const Layout = @import("../recursion/air/block_v5_memory_source_page_fixed_layout_v1.zig");
const NativeRecorder = @import("../recursion/air/blake3_native_recorder.zig");
const Sink = @import("../recursion/air/blake3_fixed_operation_recorder_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Fixed = @import("../recursion/block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Observed = struct {
    builder: *Frames.Builder,
    native: core.channel.blake3.Channel = .{},
    pub fn mixU32s(self: *@This(), values: []const u32) void {
        self.builder.mixU32s(values);
        self.native.mixU32s(values);
    }
    pub fn mixRoot(self: *@This(), value: [32]u8) void {
        self.builder.mixRoot(value);
        self.native.mixRoot(value);
    }
    pub fn mixU64(self: *@This(), value: u64) void {
        self.builder.mixU64(value);
        self.native.mixU64(value);
    }
    pub fn mixFelts(self: *@This(), values: []const Q) void {
        self.builder.mixFelts(values);
        self.native.mixFelts(values);
    }
    pub fn drawSecureFelts(self: *@This(), a: std.mem.Allocator, count: usize) ![]Q {
        try self.builder.check();
        return self.native.drawSecureFelts(a, count);
    }
};
fn pcsConfig() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 1) };
}
fn rawMetadata() !struct { plan: RawSchema.Protocol.Plan, pin: Raw.Pin } {
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    const plan = try RawSchema.Protocol.init(&admitted.source, try pcsConfig(), .{ .page_row_log = 1 });
    const page = try plan.page(0);
    const geometry = try @import("block_v5_memory_source_packed_sha_columns_v1.zig").Geometry.fromPage(&admitted.source, page, .{});
    const roots: [6][32]u8 = .{ @splat(13), @splat(14), @splat(15), @splat(16), @splat(17), @splat(18) };
    const pin = Raw.Pin{ .raw = .{ .plan_id = plan.identity, .page = page, .roots = roots[0..2].*, .config = plan.config }, .geometry = geometry, .roots = roots };
    try pin.require(&admitted.source, plan, .{ .first = .{ .page_row_log = 1 } });
    return .{ .plan = plan, .pin = pin };
}
fn foldMetadata() !struct { plan: Protocol.FoldPlan, pin: Protocol.FoldPin } {
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    const plan = try Protocol.FoldPlan.init(&admitted, .{ .empty = 1, .roots = 1 }, try pcsConfig(), .{ .page_row_log = 1 });
    const root = admitted.source.pins.expected_final_rw_root;
    const operations = [_]@import("block_v5_memory_source_batch_fold_v1.zig").Operation{
        .{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
        .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
    };
    const geometry = try @import("block_v5_memory_source_packed_blake_columns_v1.zig").Geometry.fromOperations(&operations, 100, .{});
    const pin = Protocol.FoldPin{ .page = try plan.page(0), .plan_id = plan.identity, .inventory_id = @splat(19), .geometry = geometry, .roots = .{ @splat(13), @splat(14), @splat(15), @splat(16), @splat(17), @splat(18) } };
    try pin.require(&admitted, plan, .{ .page_row_log = 1 });
    return .{ .plan = plan, .pin = pin };
}
fn framingEpoch(a: std.mem.Allocator) !Protocol.SourceEpoch {
    // Fully initialized untrusted public framing proposal, not Context or an
    // authenticated source epoch. Actual native draws avoid invented elements.
    var channel = core.channel.blake3.Channel{};
    channel.mixRoot(@splat(14));
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    const values = try channel.drawSecureFelts(a, 24);
    defer a.free(values);
    return .{ .seal_digest = @splat(14), .after_draw_digest = channel.digestBytes(), .challenges = .{
        .source = .{ .word = word, .bytes = .init(values[0], values[1]), .input = .init(values[2], values[3]), .insertion = .init(values[4], values[5]), .before = .init(values[6], values[7]), .after = .init(values[8], values[9]), .route = .init(values[10], values[11]), .roots = .init(values[12], values[13]), .ordering = .init(values[14], values[15]), .sha_chain = .init(values[16], values[17]) },
        .route = .init(values[18], values[19]),
        .indexed = .init(values[20], values[21]),
        .hash = .init(values[22], values[23]),
    } };
}
fn oldClaimFrames(comptime kind: Semantic.Kind, channel: anytype, claims: @import("block_v5_memory_source_unified_page_components_v1.zig").ForKind(kind).Claims) void {
    // Independent retained pre-extraction byte oracle.
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x434c414d, @intFromEnum(kind) });
    channel.mixRoot(Page.ForKind(kind).abiId());
    channel.mixFelts(&claims.core);
    channel.mixFelts(&claims.capture.sums);
    channel.mixU64(claims.capture.wire_requests);
    channel.mixFelts(&claims.source_inputs.sums);
    channel.mixU64(claims.source_inputs.requests);
    channel.mixFelts(&claims.capture_inputs.sums);
    channel.mixU64(claims.capture_inputs.requests);
    channel.mixFelts(&claims.arithmetic);
}
fn parity(comptime kind: Semantic.Kind) !void {
    const a = std.testing.allocator;
    const OriginalFixture = if (kind == .raw) @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").Fixture else @import("block_v5_memory_source_page_recursive_test_v1.zig").Fixture;
    const meta = try if (kind == .raw) rawMetadata() else foldMetadata();
    const epoch = try framingEpoch(a);
    var fixture = try OriginalFixture.init(a);
    defer fixture.deinit();
    var builder = Frames.Builder{ .allocator = a };
    defer builder.deinit();
    var observed = Observed{ .builder = &builder };
    // Original concrete first/semantic/draw byte sequence, independently of
    // the new count-only Layout. No source/proof acceptance occurs here.
    if (kind == .raw) try Raw.replayInto(&observed, meta.plan, meta.pin) else {
        Protocol.mixFoldFirst(&observed, meta.plan, meta.pin);
        for (meta.pin.roots) |root| observed.mixRoot(root);
    }
    observed.mixRoot(Page.ForKind(kind).abiId());
    try Protocol.beginSemantic(&observed, kind, fixture.frame.semantic.premix_identity, epoch, fixture.graph, fixture.frame.semantic.claims);
    const semantic_start = builder.root_count;
    for (fixture.frame.semantic.roots) |root| observed.mixRoot(root);
    const relations = try Protocol.drawPageRelations(a, &observed, fixture.frame.semantic, fixture.frame.semantic);
    try builder.check();
    const first = try builder.steps.toOwnedSlice(a);
    defer a.free(first);
    const component_claim_first = builder.fields.items.len;
    oldClaimFrames(kind, &observed, fixture.frame.claims);
    try builder.check();
    const claim_steps = try builder.steps.toOwnedSlice(a);
    defer a.free(claim_steps);
    var layout = try Layout.deriveForMetadata(kind, a, meta.plan, meta.pin, epoch, fixture.frame.semantic.premix_identity, fixture.graph, fixture.frame.semantic.claims, .{});
    defer layout.deinit();
    try std.testing.expectEqualDeep(first, layout.first);
    try std.testing.expectEqualDeep(claim_steps, layout.claims);
    try std.testing.expectEqual(builder.data.items.len, layout.word_count);
    try std.testing.expectEqual(builder.fields.items.len, layout.field_count);
    try std.testing.expectEqual(component_claim_first, layout.component_claim_first);
    try std.testing.expectEqualDeep(builder.root_offsets[semantic_start..][0..2].*, layout.roots_offset[6..8].*);
    // Independently replay the new shared live prefix and actual Universal47.
    var direct = core.channel.blake3.Channel{};
    try Prefix.sourceFirst(kind, &direct, meta.plan, meta.pin);
    try Prefix.beginSemantic(kind, &direct, fixture.frame.semantic.premix_identity, epoch, fixture.graph, fixture.frame.semantic.claims);
    for (fixture.frame.semantic.roots) |root| direct.mixRoot(root);
    const new_relations = try Protocol.drawPageRelations(a, &direct, fixture.frame.semantic, fixture.frame.semantic);
    Page.ForKind(kind).mixClaims(&direct, fixture.frame.claims);
    try std.testing.expectEqualDeep(relations, new_relations);
    try std.testing.expectEqualDeep(observed.native, direct);
    // Original public coordinates -> live Recorder vs count-only fixed Sink.
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const frame = Frames.Statement{ .allocator = a, .words = builder.data.items, .felts = builder.fields.items, .first = first, .claims = claim_steps, .sealed_offset = 0, .roots_offset = layout.roots_offset[0..3].* };
    var live = NativeRecorder.Recorder{ .a = temp, .universal_relations = true };
    try frame.recordAt(&live, first, Layout.publicCircuit(kind));
    try live.skipCommittedRootsFor(8);
    const replay_relations = try Universal.UniversalRelations.draw(temp, &live);
    try frame.recordAt(&live, claim_steps, Layout.publicCircuit(kind));
    try live.check();
    try std.testing.expectEqualDeep(replay_relations, relations);
    try std.testing.expectEqualDeep(live.native, observed.native);
    var fixed = Sink.Recorder{ .a = temp, .limits = .{} };
    try layout.record(&fixed, layout.first, Layout.publicCircuit(kind));
    try fixed.skipCommittedRootsFor(8);
    try fixed.universalPairs(0, Universal.RELATION_COUNT);
    try layout.record(&fixed, layout.claims, Layout.publicCircuit(kind));
    try compareRouting(live.operations.items, fixed.operations.items);
    const view = try @import("block_v5_native_fixed_pcs_test_v1.zig").PageView.init(a, fixture.owner.composition.?);
    defer view.deinit();
    var plan = try Fixed.ForKind(kind).recordForLayout(a, &layout, view, 1, .{});
    defer plan.deinit();
    try plan.validate();
    try std.testing.expectEqual(@as(usize, 1), plan.fixed.query_outputs.len);
    // Domain/index/claim coordinate mutation changes the actual trusted key
    // metadata; it does not assert satisfaction from a host scalar checksum.
    const saved = layout.claims[0];
    layout.claims[0] = .{ .words = .{ .first = 0, .len = 1 } };
    var changed = try Fixed.ForKind(kind).recordForLayout(a, &layout, view, 1, .{});
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(plan.id, changed.id));
    layout.claims[0] = saved;
    const roots_slot = @import("../recursion/air/blake3_root_sources.zig");
    try std.testing.expectEqual(@as(u32, 64), (try roots_slot.caller(8)).first_wire);
    try std.testing.expectEqual(@as(u32, 72), (try roots_slot.caller(9)).first_wire);
    try std.testing.expectEqual(@as(u32, 80), (try roots_slot.caller(10)).first_wire);
}
fn compareRouting(live: []const @import("../recursion/air/blake3_transcript_witness.zig").Operation, fixed: @TypeOf(live)) !void {
    try std.testing.expectEqual(live.len, fixed.len);
    for (live, fixed) |actual, expected| {
        try std.testing.expectEqual(std.meta.activeTag(actual), std.meta.activeTag(expected));
        switch (actual) {
            .routed_words => |x| {
                try std.testing.expectEqualDeep(x.source, expected.routed_words.source);
                try std.testing.expectEqual(x.values.len, expected.routed_words.values.len);
            },
            .routed_felts => |x| {
                try std.testing.expectEqualDeep(x.source, expected.routed_felts.source);
                try std.testing.expectEqual(x.values.len, expected.routed_felts.values.len);
            },
            .routed_root => |x| try std.testing.expectEqualDeep(x.source, expected.routed_root.source),
            .routed_integer => |x| try std.testing.expectEqualDeep(x.source, expected.routed_integer.source),
            .secure => |x| {
                try std.testing.expectEqualDeep(x.output, expected.secure.output);
                try std.testing.expectEqual(x.consumption, expected.secure.consumption);
            },
            else => return error.UnexpectedPageFixedPrefixOperation,
        }
    }
}
test "PAGE fixed transcript: original raw first six roots semantic epoch47 and claims exact native parity" {
    try parity(.raw);
}
test "PAGE fixed transcript: original fold first six roots semantic epoch47 and claims exact native parity" {
    try parity(.fold);
}
fn countAllocation(a: std.mem.Allocator) !void {
    var builder = Layout.Builder{ .a = a, .limits = .{} };
    defer builder.deinit();
    builder.mixU32s(&.{ 1, 2, 3 });
    builder.mixRootCount();
    builder.mixIntegerCount();
    builder.mixFeltsCount(7);
    try builder.check();
    const steps = try builder.steps.toOwnedSlice(a);
    defer a.free(steps);
}
test "PAGE fixed transcript: count-only layout allocator failures preserve original OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, countAllocation, .{});
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var builder = Layout.Builder{ .a = deny.allocator(), .limits = .{} };
    defer builder.deinit();
    builder.mixRootCount();
    builder.mixFeltsCount(std.math.maxInt(usize));
    try std.testing.expectError(error.OutOfMemory, builder.check());
}
test "PAGE fixed transcript: bounds canonical public fields and old root grammar remain closed" {
    var builder = Layout.Builder{ .a = std.testing.allocator, .limits = .{ .max_words = 8 } };
    defer builder.deinit();
    builder.mixRootCount();
    builder.mixIntegerCount();
    try std.testing.expectError(error.SourcePageFixedLayoutResourceLimit, builder.check());
    var invalid = Layout.Builder{ .a = std.testing.allocator, .limits = .{} };
    defer invalid.deinit();
    var value = Q.zero();
    value.c0.a.v = core.fields.m31.Modulus;
    invalid.mixFelts(&.{value});
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, invalid.check());
    var r = Sink.Recorder{ .a = std.testing.allocator, .limits = .{} };
    defer r.operations.deinit(std.testing.allocator);
    r.mixRoot(@splat(1));
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, r.skipCommittedRoots(8));
    try r.skipCommittedRootsFor(8);
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, r.skipCommittedRootsFor(8));
}
test "PAGE fixed transcript: count owner lease is held until final frees" {
    const owner = try Budget.create(std.testing.allocator, 1 << 20);
    var active = true;
    defer if (active) owner.destroy();
    const lease = owner.retain();
    var builder = Layout.Builder{ .a = owner.allocator(), .limits = .{} };
    defer {
        builder.deinit();
        lease.destroy();
    }
    builder.mixRootCount();
    builder.mixFeltsCount(8);
    owner.destroy();
    active = false;
    try builder.check();
}
