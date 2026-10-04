//! Fresh-verifier gate for the RW first-touch source and shared BLAKE3 path.
const std = @import("std");
const core = @import("stwo_core");
const f = @import("../../recursion/air/blake3_proof_fixture.zig");
const gate = @import("../../recursion/air/blake3_proof_gate_test_support.zig");
const roster = @import("../../recursion/air/blake3_fixture_roster.zig");
const hash = @import("../block_rw_initial_hash_rows_v2.zig");
const shared = @import("../blake3_shared_path_emit.zig");
const air = @import("../block_rw_initial_air_v2.zig");
const rw = @import("../block_rw_initial_provider_v2.zig");
const snapshot_mod = @import("../../recursion/air/blake3_memory_snapshot.zig");
const state = @import("../../runner/memory_state.zig");
const spans = @import("../../recursion/span_statement_blake3.zig");
const manifest = @import("../block_commitment_manifest.zig");
const source_seal = @import("../block_memory_source_seal_v2.zig");
const bus = @import("../block_memory_relation_v2.zig");
const stark = @import("../block_rw_initial_provider_stark_v2.zig");

const Roster = roster.WithExtras(.{ hash.route, hash.private, hash.bridge, air });
const ProofState = struct {
    base: manifest.Sealed,
    roster_digest: [32]u8,
    plan: *const rw.Plan,
    fixed_trace: *const rw.Trace,
    placement: stark.Placement,
    sealed: ?source_seal.SourceSeal = null,
    challenges: ?bus.Challenges = null,
    interaction: ?rw.Interaction = null,
    component: ?stark.Component = null,
    pub fn deinit(self: *ProofState) void {
        if (self.interaction) |*value| value.deinit();
    }
};
const Protocol = struct {
    state: *ProofState,
    pub const EXTRA_COMPONENT_COUNT: usize = 1;
    pub const EXTRA_COMPOSITION_LOG_SPLIT: u32 = stark.expansion_bits;
    pub fn config(_: @This()) !core.pcs.PcsConfig {
        return .{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    }
    pub fn mix(self: @This(), channel: *f.Channel) !void {
        channel.* = (self.state.sealed orelse return error.UnboundInitialRwSourceSeal).sharedChannel();
    }
    pub fn bindFirstRound(self: @This(), fixed_root: f.Hasher.Hash, main_root: f.Hasher.Hash) !void {
        const entry = source_seal.FirstRoundEntry{ .family = .initial_rw, .index = 0, .roots = .{ fixed_root, main_root } };
        self.state.sealed = try source_seal.SourceSeal.initBound(self.state.base, 0, self.state.roster_digest, 1, 1, @splat(0), source_seal.digestFirstRoundRoster(&.{entry}));
    }
    pub fn drawRelations(self: @This(), a: std.mem.Allocator, _: *f.Channel) !f.universal.UniversalRelations {
        // Every block-v2 component derives the same bus challenges from the
        // globally bound root roster. Its local PCS cursor mixes its own roots
        // separately for composition/openings.
        const drawn = try bus.Challenges.draw(a, self.state.sealed orelse return error.UnboundInitialRwSourceSeal);
        if (self.state.challenges) |existing| {
            try std.testing.expectEqualDeep(existing, drawn);
        } else {
            self.state.challenges = drawn;
            self.state.interaction = try self.state.plan.interaction(&self.state.challenges.?);
            self.state.component = try stark.Component.init(self.state.interaction.?.claim, &self.state.challenges.?, self.state.placement);
        }
        return drawn.universal_prefix;
    }
    pub fn appendExtraFixed(self: @This(), a: std.mem.Allocator, columns: *std.ArrayList(f.Column)) !void {
        try columns.append(a, .{ .log_size = self.state.fixed_trace.log_size, .values = self.state.fixed_trace.fixed[8] });
        try columns.append(a, .{ .log_size = self.state.fixed_trace.log_size, .values = self.state.fixed_trace.fixed[9] });
    }
    pub fn appendExtraMain(self: @This(), a: std.mem.Allocator, columns: *std.ArrayList(f.Column)) !void {
        for (self.state.fixed_trace.main) |values| try columns.append(a, .{ .log_size = self.state.fixed_trace.log_size, .values = values });
    }
    pub fn appendExtraInteraction(self: @This(), a: std.mem.Allocator, columns: *std.ArrayList(f.Column)) !void {
        const interaction = self.state.interaction orelse return error.MissingInitialRwInteraction;
        for (interaction.columns) |values| try columns.append(a, .{ .log_size = interaction.claim.log_size, .values = values });
    }
    pub fn mixExtraClaims(self: @This(), channel: *f.Channel) !void {
        (self.state.interaction orelse return error.MissingInitialRwInteraction).claim.mixInteraction(channel);
    }
    pub fn extraProverHandles(self: @This()) [1]f.prover.air.component_prover.ComponentProver {
        return .{self.state.component.?.asProverComponent()};
    }
    pub fn extraVerifierHandles(self: @This()) [1]core.air.components.Component {
        return .{self.state.component.?.asVerifierComponent()};
    }
    pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
    pub fn mixClaims(_: @This(), channel: *f.Channel, claims: []const f.QM31) !void {
        f.mixClaims(channel, claims);
    }
    pub fn observeProof(self: @This(), a: std.mem.Allocator, proof: anytype, prove_ns: u64) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(a);
        try @import("interop_postcard").serializeProof(f.Hasher, bytes.writer(a), proof.*);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes.items, &digest, .{});
        std.debug.print("RW_JOINT mode={s} q70/pow26 prove_ns={d} proof_bytes={d} proof_sha256={s}\n", .{ if (self.state.plan.zero_query) "zero_query" else "complete_sparse", prove_ns, bytes.items.len, &std.fmt.bytesToHex(digest, .lower) });
    }
    pub fn observeVerified(_: @This(), verify_ns: u64) !void {
        std.debug.print("RW_JOINT verify_ns={d}\n", .{verify_ns});
    }
};
fn log(rows: usize) u32 {
    return if (rows <= 1) 1 else std.math.log2_int_ceil(usize, rows);
}

test "RW provider and shared BLAKE3 path close typed universal relations in one PCS proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const layout = state.MemoryLayout{
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
    var words = [_]state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x12345678, .final_word = 0x12345678, .final_clock = 0 },
        .{ .addr = 0x2000, .initial_word = 0xdeadbeef, .final_word = 0xdeadbeef, .final_clock = 0, .role = .{ .is_public_input = true } },
    };
    const snapshot = state.Snapshot{ .layout = layout, .segment_role = .single(), .words = &words };
    var projection = try snapshot_mod.fromSnapshot(a, &snapshot, .entry, .continuation);
    defer projection.deinit();
    const machine = try spans.MachineState.init(0, @splat(0), projection.root, .{ .bytes = @splat(0) });
    const complete = try spans.CompleteExecution.init(.{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, machine, machine, .{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, 1);
    const job = try spans.JobContext.init(complete, 1);
    var plan = try rw.Plan.initCompleteSparseBorrowed(a, &projection, layout, job, &.{ 0x1000, 0x2000 }, 100, 200);
    defer plan.deinit();
    try std.testing.expectError(error.UntrustedInitialRwRoster, rw.trustedFixedTrace(a, job, layout, plan.addresses, 100, 200, plan.rosterDigest()));
    var verified_fixed = try rw.trustedCompleteSparseFixedTrace(a, job, layout, plan.addresses, 100, 200, plan.rosterDigest());
    defer verified_fixed.deinit();
    var hidden_words = [_]state.WordState{
        words[0], .{ .addr = 0x1004, .initial_word = 99, .final_word = 99, .final_clock = 0 }, words[1],
    };
    const hidden_snapshot = state.Snapshot{ .layout = layout, .segment_role = .single(), .words = &hidden_words };
    var hidden_projection = try snapshot_mod.fromSnapshot(a, &hidden_snapshot, .entry, .continuation);
    defer hidden_projection.deinit();
    const hidden_machine = try spans.MachineState.init(0, @splat(0), hidden_projection.root, .{ .bytes = @splat(0) });
    const hidden_complete = try spans.CompleteExecution.init(.{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, hidden_machine, hidden_machine, .{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, 1);
    const hidden_job = try spans.JobContext.init(hidden_complete, 1);
    var incomplete = try rw.Plan.initCompleteSparseBorrowed(a, &hidden_projection, layout, hidden_job, &.{ 0x1000, 0x2000 }, 100, 200);
    defer incomplete.deinit();
    var rejected_rows = hash.Rows.init(a);
    defer rejected_rows.deinit();
    try std.testing.expectError(error.IncompleteSparseMemoryRoster, incomplete.emitPaths(&rejected_rows));
    try provePlan(a, &plan);
    var left_shard = try rw.Plan.initCompleteSparseShardBorrowed(a, &projection, layout, job, &.{0x1000}, 201, 300, .{ .level = 11, .index = 0 });
    defer left_shard.deinit();
    var trusted_shard = try rw.trustedSparseShardFixedTrace(a, job, layout, left_shard.addresses, 201, 300, left_shard.shard_coordinate.?, left_shard.shard_root.?, left_shard.rosterDigest());
    defer trusted_shard.deinit();
    try provePlan(a, &left_shard);
    const hasher = @import("../../air/memory_commitment/blake3_state_tree.zig").TreeHasher.init(.memory);
    var right_root: [1]@TypeOf(left_shard.shard_root.?) = undefined;
    try hasher.subtreeRoots(projection.leaves, &.{.{ .level = 11, .index = 1 }}, &right_root);
    const roots = [_]rw.sparse_shards.Root{
        .{ .coordinate = left_shard.shard_coordinate.?, .digest = left_shard.shard_root.? },
        .{ .coordinate = .{ .level = 11, .index = 1 }, .digest = right_root[0] },
    };
    try std.testing.expectEqualDeep(projection.root, try rw.sparse_shards.assemble(&roots));
    var tampered_roots = roots;
    tampered_roots[0].digest.bytes[0] ^= 1;
    try std.testing.expect(!std.meta.eql(projection.root, try rw.sparse_shards.assemble(&tampered_roots)));
    var dense: [4097]u32 = undefined;
    for (&dense, 0..) |*address, i| address.* = @intCast(i);
    const adaptive = try rw.sparse_shards.plan(a, &dense);
    for (adaptive) |shard| try std.testing.expect(shard.end - shard.first <= rw.sparse_shards.MAX_LEAVES_PER_SHARD);
    var hidden_shard = try rw.Plan.initCompleteSparseShardBorrowed(a, &hidden_projection, layout, hidden_job, &.{0x1000}, 201, 300, .{ .level = 11, .index = 0 });
    defer hidden_shard.deinit();
    try std.testing.expectError(error.IncompleteSparseMemoryRoster, hidden_shard.emitPaths(&rejected_rows));
    var zero_plan = try rw.Plan.initZeroQueryBorrowed(a, &projection, layout, job, &.{0x1004}, 300, 400);
    defer zero_plan.deinit();
    try std.testing.expectError(error.UntrustedInitialRwRoster, rw.trustedFixedTrace(a, job, layout, zero_plan.addresses, 300, 400, zero_plan.rosterDigest()));
    var zero_fixed = try rw.trustedZeroQueryFixedTrace(a, job, layout, zero_plan.addresses, 300, 400, zero_plan.rosterDigest());
    defer zero_fixed.deinit();
    try provePlan(a, &zero_plan);
    try std.testing.expectError(error.NonzeroInitialRwZeroQuery, rw.Plan.initZeroQueryBorrowed(a, &projection, layout, job, &.{0x1000}, 500, 600));
}

fn provePlan(a: std.mem.Allocator, plan: *const rw.Plan) !void {
    const roster_digest = try rw.digestRosterSet(&.{plan.rosterDigest()});
    var initial_trace = try plan.trace();
    defer initial_trace.deinit();
    var live = hash.Rows.init(a);
    defer live.deinit();
    _ = try plan.emitPaths(&live);
    const logs: [Roster.Airs.len]u32 = .{
        log(live.g_rows.items.len),     log(live.xor_rows.items.len),     log(live.boundary_rows.items.len),
        log(live.route_rows.items.len), log(live.private_rows.items.len), log(live.bridge_rows.items.len),
        @max(2, log(plan.rows.len)),
    };
    const rows = .{
        try f.padded(hash.g, a, live.g_rows.items, logs[0]),
        try f.padded(hash.xor, a, live.xor_rows.items, logs[1]),
        try f.padded(hash.boundary, a, live.boundary_rows.items, logs[2]),
        try f.padded(hash.route, a, live.route_rows.items, logs[3]),
        try f.padded(hash.private, a, live.private_rows.items, logs[4]),
        try f.padded(hash.bridge, a, live.bridge_rows.items, logs[5]),
        try f.padded(air, a, plan.rows, logs[6]),
    };
    const placement = try (Roster.Manifest{ .log_sizes = logs }).placement(@enumFromInt(Roster.Airs.len - 1));
    const universal_interaction_count: usize = comptime blk: {
        var count: usize = 0;
        for (Roster.Airs) |Air| count += Air.INTERACTION_COLUMN_COUNT;
        break :blk count;
    };
    const path_root = plan.shard_root orelse plan.source.root;
    const trusted = try preprocessing(a, plan, path_root, logs);
    var wrong = path_root;
    wrong.bytes[0] ^= 1;
    const false_pp = try preprocessing(a, plan, wrong, logs);
    var proof_state = ProofState{ .base = .{ .digest = @splat(17), .instance_count = 1 }, .roster_digest = roster_digest, .plan = plan, .fixed_trace = &initial_trace, .placement = .{
        .fixed_offset = placement.preprocessed_offset,
        .main_offset = placement.main_offset + air.PHYSICAL_MAIN_COLUMN_COUNT + f.kinds.len,
        .interaction_offset = universal_interaction_count + f.kinds.len * 4,
    } };
    defer proof_state.deinit();
    try gate.ForBackend(f.Cpu).runForParametersProtocol(Roster, a, rows, logs, trusted, false_pp, @as([Roster.Airs.len][0]f.M31, @splat(.{})), Protocol{
        .state = &proof_state,
    }, void);
    const sealed = proof_state.sealed orelse return error.UnboundInitialRwSourceSeal;
    const memory_challenges = try bus.Challenges.draw(a, sealed);
    const table_challenges = try bus.Challenges.draw(a, sealed);
    try std.testing.expectEqualDeep(proof_state.challenges.?, memory_challenges);
    try std.testing.expectEqualDeep(proof_state.challenges.?, table_challenges);
    var direct_channel = sealed.sharedChannel();
    try std.testing.expectEqualDeep(proof_state.challenges.?, try bus.Challenges.drawFromChannel(a, &direct_channel));
}

fn preprocessing(a: std.mem.Allocator, plan: *const rw.Plan, root: @import("../../air/memory_commitment/blake3_state_tree.zig").Digest, logs: [Roster.Airs.len]u32) ![]f.Column {
    var fixed_hash = hash.Rows.init(a);
    defer fixed_hash.deinit();
    _ = if (plan.shard_coordinate) |coordinate|
        try shared.emitCompleteSparseSubtree(a, plan.path_inputs, plan.path_namespace, .memory, root, null, coordinate, &fixed_hash)
    else if (plan.complete_sparse)
        try shared.emitCompleteSparse(a, plan.path_inputs, plan.path_namespace, .memory, root, null, &fixed_hash)
    else
        try shared.emit(a, plan.path_inputs, plan.path_namespace, .memory, root, null, &fixed_hash);
    const provider_rows = try a.alloc(air.Row, plan.addresses.len);
    for (provider_rows, plan.addresses, 0..) |*row, address, i| row.* = try air.fixedRowWithSelectors(address, plan.caller_base, @intCast(i), !plan.zero_query, true);
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (Roster.Airs, .{
        fixed_hash.g_rows.items,     fixed_hash.xor_rows.items,     fixed_hash.boundary_rows.items,
        fixed_hash.route_rows.items, fixed_hash.private_rows.items, fixed_hash.bridge_rows.items,
        provider_rows,
    }, 0..) |Air, typed_rows, i| try f.project(Air, a, typed_rows, logs[i], 0, &columns);
    const size: usize = @as(usize, 1) << @intCast(logs[6]);
    const first = try a.alloc(f.M31, size);
    const last = try a.alloc(f.M31, size);
    @memset(first, f.M31.zero());
    @memset(last, f.M31.zero());
    const committed = @import("../../recursion/air/framework_interaction.zig").committedRow;
    first[committed(0, logs[6])] = f.M31.one();
    last[committed(size - 1, logs[6])] = f.M31.one();
    try columns.append(a, .{ .log_size = logs[6], .values = first });
    try columns.append(a, .{ .log_size = logs[6], .values = last });
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
