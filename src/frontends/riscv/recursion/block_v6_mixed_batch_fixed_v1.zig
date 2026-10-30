//! Capture-free ORIGINAL mixed-batch verifier roster. Source admission is
//! reconstructed from independent key/range policy and typed proposed claims.
//! This is not yet a complete reduction-root key or qualified batch proof.
const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("block_v6_mixed_batch_capture_v1.zig");
const Bus = @import("block_v6_mixed_batch_public_v1.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Shape = @import("block_v5_recursive_parent_shape_v1.zig").Shape;
const Composition = @import("air/block_v5_open_parent_composition_v2.zig");
const Arithmetic = @import("air/block_v5_recursive_parent_fixed_arithmetic_v1.zig");
const Transcript = @import("air/block_v5_recursive_parent_fixed_transcript_v1.zig");
const Queries = @import("air/blake3_query_links.zig");
const Paths = @import("air/blake3_stark_paths.zig");
const PiecesModule = @import("block_v5_recursive_parent_fixed_pieces_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").ForAdmission(Admission);
const Pieces = PiecesModule.ForAdmission(Admission);
const Sources = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig").ForPackedPieces(Pieces.Owned);
const Roster = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Packed = @import("air/block_v5_requester_recursive_packed_fixed_v1.zig");
const Openings = @import("air/block_v5_recursive_parent_fixed_openings_v1.zig");
const FixedRecorder = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Operations = @import("block_v5_recursive_parent_operations_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Capture.Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    fn init(source: *const Capture.Source) Admission {
        return .{ .source = source, .key = source.geometry(), .expected_id = source.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        if (self.pc_clock_children.len != 0) return error.UntrustedMixedBatchFrames;
        const original = Capture.Admission{ .source = self.source, .key = self.key, .expected_id = self.expected_id };
        try original.validate();
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
pub const Limits = struct { max_bytes: usize = 4 << 30, capture: Capture.Limits = .{}, pieces: PiecesModule.Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    source: *Capture.Source,
    fixed: Storage.FixedTuple(false),
    namespace: Namespace.Plan,
    wires: []Bus.Wire,
    context: Base.Context,
    pub const fixed_setup_only = true;
    pub const complete_original_verifier_setup = true;
    pub const live_parity_qualified = false;
    pub const complete_block_authority = false;
    pub fn derive(backing: std.mem.Allocator, policy: Capture.Policy, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or capacity == 0) return error.MixedBatchResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const source = try Capture.Source.create(a, policy, limits.capture);
        errdefer source.deinit();
        const admission = Admission.init(source);
        const pieces = try compilePieces(a, &admission, capacity, limits.pieces);
        defer pieces.deinit();
        const assembly = try Assembly.Owned.init(a, pieces, &admission);
        defer assembly.deinit();
        const sources = try Sources.Owned.init(a, pieces, source.original_key.preprocessed_root);
        defer sources.deinit();
        var packed_ports = try Packed.Owned.init(a, pieces.composition, source.terms, .{});
        defer packed_ports.deinit();
        const openings = try Openings.Owned.init(a, pieces.shape, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph, &pieces.paths, &assembly.pcs.projection);
        defer openings.deinit();
        const fixed = try Roster.compileOriginalRoster(a, sources, &packed_ports, openings, assembly.pcs, &pieces.transcript.fixed, &pieces.paths, &assembly.arithmetic, assembly.selectors, &pieces.arithmetic.deep_graph);
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &assembly.arithmetic.plan, .reference = assembly.arithmetic.reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        var wires: std.ArrayList(Bus.Wire) = .empty;
        errdefer wires.deinit(a);
        try @import("block_v6_mixed_batch_prepare_v1.zig").collectFixed(a, &wires, &pieces.transcript.fixed, &pieces.composition, source.terms.len, 0);
        const context = Base.Context{ .child_key_id = source.expected_id, .child_config = source.original_key.config, .graph_ids = assembly.graph_ids, .transcript_plan_id = assembly.transcript_id };
        _ = try Base.contextIdentity(context);
        try source.requirePolicy(a, policy, limits.capture);
        return .{ .allocator = a, .budget = budget, .source = source, .fixed = fixed, .namespace = namespace, .wires = try wires.toOwnedSlice(a), .context = context };
    }
    pub fn validateLive(self: *const Owned, live: *@import("blake3_execution_parent_preparation.zig").Prepared, wires: []const Bus.Wire) !void {
        try live.rows.partitionHashRows();
        try self.namespace.validateLive(&live.rows);
        if (!std.meta.eql(self.context, live.context) or self.wires.len != wires.len) return error.UntrustedMixedBatchFixed;
        for (self.wires, wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedMixedBatchFixed;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.rows.fixed[i].len) return error.UntrustedMixedBatchFixed;
            for (self.fixed[i], live.rows.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedMixedBatchFixed;
        }
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        self.namespace.deinit();
        self.allocator.free(self.wires);
        inline for (0..Storage.Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.source.deinit();
        self.* = undefined;
        budget.destroy();
    }
};
fn compilePieces(a: std.mem.Allocator, admission: *const Admission, capacity: u32, limits: PiecesModule.Limits) !*Pieces.Owned {
    const shape = try Shape.initForAdmission(a, admission, limits.shape);
    errdefer shape.deinit();
    var composition = try Composition.compileShape(a, admission);
    errdefer composition.deinit();
    const arithmetic = try Arithmetic.Owned.init(a, shape, limits.arithmetic);
    errdefer arithmetic.deinit();
    var transcript = try compileTranscript(a, admission, shape, capacity, limits.transcript);
    errdefer transcript.deinit();
    var queries = try Queries.build(a, transcript.fixed.fixed.query_outputs, &arithmetic.deep_graph, &arithmetic.fri_graph, shape.config.fri_config.n_queries, shape.widths.len);
    errdefer queries.deinit();
    var paths = try Paths.compileFixedShape(a, shape, &queries);
    errdefer paths.deinit();
    const pieces = try a.create(Pieces.Owned);
    pieces.* = .{ .allocator = a, .budget = null, .shape = shape, .composition = composition, .arithmetic = arithmetic, .transcript = transcript, .queries = queries, .paths = paths };
    return pieces;
}
fn compileTranscript(a: std.mem.Allocator, admission: *const Admission, shape: *const Shape, capacity: u32, limits: Transcript.Limits) !Transcript.Owned {
    try shape.validateAgainst(admission);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var recorder = FixedRecorder.Recorder{ .a = temp, .limits = limits };
    admission.source.replayShape(&recorder);
    if (recorder.failure) |err| return err;
    var suffix: std.ArrayList(Operations.Operation) = .empty;
    try Operations.appendClosedSuffix(temp, &suffix, shape);
    var frames: usize = 0;
    for (suffix.items) |*operation| {
        if (operation.* == .claim_frame) {
            // The original mixed protocol has a distinct domain/version. All
            // original PCS/challenge/query operations remain byte-for-byte.
            operation.claim_frame.tag = .{ Protocol.CLAIM_TAG, Protocol.VERSION, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT };
            frames += 1;
        }
        try recorder.suffix(operation.*);
    }
    if (frames != 1) return error.InvalidMixedBatchTranscript;
    const fixed = try Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
    return .{ .allocator = a, .budget = null, .fixed = fixed, .shape_id = shape.seal };
}
test "mixed batch independent original fixed compiler reconstructs exact routed metadata" {
    // Geometry-only metadata fixture; this is not a proof or live parity gate.
    const source = try Capture.testing.metadataSource(std.testing.allocator);
    defer source.deinit();
    const policy = Capture.Policy{ .scope = source.scope, .whole_roster = source.roster, .counts = &.{1}, .ordinal = 0, .key = source.original_key, .expected_key = source.expected_id, .wires = source.wires, .values = .{ .children = source.children }, .expected_public_input_identity = source.public_input_digest };
    var fixed = try Owned.derive(std.testing.allocator, policy, 2, .{});
    defer fixed.deinit();
    try std.testing.expect(fixed.wires.len != 0);
    try fixed.namespace.requireIndependentMainPort();
    try std.testing.expectEqualDeep(source.expected_id, fixed.context.child_key_id);
    var cells: usize = 0;
    inline for (Storage.Airs, 0..) |Air, i| cells += fixed.fixed[i].len * Air.PREPROCESSED_COLUMN_COUNT;
    try std.testing.expect(cells != 0);
    std.debug.print("MIXED_BATCH_COLD_SETUP fixed_cells={d} public_wires={d} namespaces={d} metadata_only=true\n", .{ cells, fixed.wires.len, fixed.namespace.original.old.len });
}
