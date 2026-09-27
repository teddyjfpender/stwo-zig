//! One admitted full-width execution capture to owned parent rows. Hash witnesses
//! are written directly into final columns through the existing shared layout.
const std = @import("std");
const core = @import("stwo_core");
const ParentVerified = @import("blake3_native_parent_verifier.zig").Verified;
const rows_mod = @import("air/blake3_native_parent_rows.zig");
const source_mod = @import("air/blake3_execution_parent_sources.zig");
pub const Aggregation = struct {
    right_child_key_id: [32]u8,
    right_config: core.pcs.PcsConfig,
    right_graph_ids: [3][32]u8,
    right_transcript_plan_id: [32]u8,
    child_statement_ids: [2][32]u8,
    child_span_binding_ids: [2][32]u8,
    namespace_ids: [2][32]u8,
};
pub const Context = struct {
    child_key_id: [32]u8,
    child_config: core.pcs.PcsConfig,
    graph_ids: [3][32]u8,
    transcript_plan_id: [32]u8,
    statement_identity: ?[32]u8 = null,
    span_binding_id: ?[32]u8 = null,
    aggregation: ?Aggregation = null,
};
// Opt-in phase timing includes intermediate teardown, which can otherwise hide
// outside the preparation spans used to diagnose producer/prover contention.
const PreparationProfile = struct {
    timer: ?std.time.Timer,
    fn init() PreparationProfile {
        return .{ .timer = if (std.posix.getenv("STWO_RISCV_PARENT_PREPARATION_PROFILE") != null) std.time.Timer.start() catch null else null };
    }
    fn lap(self: *PreparationProfile, phase: []const u8) void {
        if (self.timer) |*timer| {
            const elapsed = timer.lap();
            std.debug.print("PARENT_PREPARATION phase={s} ns={d} thread={d}\n", .{ phase, elapsed, std.Thread.getCurrentId() });
        }
    }
};
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Prepared = struct {
    rows: rows_mod.Prepared,
    context: Context,
    allocation_budget: ?*Budget = null,
    pub fn retainedBytes(self: Prepared) !usize {
        const payload = if (self.allocation_budget) |budget| try std.math.add(usize, budget.snapshot().live_bytes, @sizeOf(Budget)) else try self.rows.retainedBytes();
        return std.math.add(usize, @sizeOf(Prepared), payload);
    }
    pub fn deinit(self: *Prepared) void {
        self.rows.deinit();
        if (self.allocation_budget) |budget| budget.destroy();
        self.* = undefined;
    }
};
/// Bounds both preparation intermediates and retained output rows. Borrowed child
/// captures, allocator overhead and stacks belong to the caller's reservation.
pub fn prepareBounded(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32, limit: usize) !Prepared {
    const budget = try Budget.create(a, limit);
    errdefer budget.destroy();
    var result = prepare(budget.allocator(), admitted, capture, expected, capacity) catch |err| {
        if (err == error.OutOfMemory and budget.snapshot().exceeded) return error.PreparationHostBudgetExceeded;
        return err;
    };
    result.allocation_budget = budget;
    return result;
}
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32) !Prepared {
    const state = try State.init(a, admitted, capture, expected, capacity);
    var profile = PreparationProfile.init();
    defer {
        state.deinit();
        profile.lap("teardown");
    }
    const result = try state.finish();
    profile.lap("assemble");
    return result;
}
/// The span is caller-admitted. Its memory transitions become actual rows in
/// this parent, with identities included in the independently derived key.
pub fn prepareSpan(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32, statement: @import("span_statement_blake3.zig").SpanStatement, conversions: [2]*const @import("air/blake3_memory_custody.zig").Prepared) !Prepared {
    var result = try prepare(a, admitted, capture, expected, capacity);
    errdefer result.deinit();
    try attachSpan(a, &result, admitted, capture, expected, statement, conversions);
    return result;
}
pub fn attachSpan(a: std.mem.Allocator, result: *Prepared, admitted: anytype, capture: anytype, expected: [32]u8, statement: @import("span_statement_blake3.zig").SpanStatement, conversions: [2]*const @import("air/blake3_memory_custody.zig").Prepared) !void {
    const binding = try @import("blake3_execution_span.zig").bind(a, admitted, capture, expected, statement, &conversions[0].plan, &conversions[1].plan);
    if (!std.mem.eql(u8, &result.context.child_key_id, &expected) or result.context.statement_identity != null or result.context.span_binding_id != null) return error.InvalidParentSpanAttachment;
    const statement_id = (try @import("span_identity_blake3.zig").hash(&try statement.canonicalWords(), .statement)).bytes;
    const binding_id = try binding.identity();
    try @import("air/blake3_parent_custody_rows.zig").extend(&result.rows, conversions, binding.conversions);
    result.context.statement_identity = statement_id;
    result.context.span_binding_id = binding_id;
}

pub const State = struct {
    allocator: std.mem.Allocator,
    context: Context,
    composition: @import("air/blake3_execution_composition.zig").Prepared,
    deep: @import("air/blake3_native_deep.zig").Prepared,
    fri: @import("air/blake3_native_fri.zig").Prepared,
    payloads: @import("air/blake3_execution_payloads.zig").Prepared,
    challenges: @import("air/blake3_execution_challenges.zig").Prepared,
    terminal: @import("air/blake3_native_terminal_encoding.zig").Prepared,
    queries: @import("air/blake3_native_queries.zig").Prepared,
    roots: @import("air/blake3_execution_roots.zig").Prepared,
    transcript: @import("air/blake3_native_transcript.zig").Prepared,
    paths: @import("air/blake3_stark_paths.zig").Prepared,
    openings: @import("air/blake3_native_openings.zig").Prepared,
    hash_columns: @import("blake3_native_hash_columns.zig").Owner,
    pub fn init(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32) !*State {
        var planned = try plan(a, admitted, capture, expected, capacity);
        defer planned.deinit();
        return planned.emit();
    }
    /// Borrow the admitted capture until emission or destruction. No final hash
    /// columns are allocated before the complete child layout is available.
    pub fn plan(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32) !Planned {
        var profile = PreparationProfile.init();
        try capture.validate(admitted, expected);
        profile.lap("validate");
        const extended = comptime @import("air/blake3_execution_profile.zig").isExtension(@TypeOf(capture.*));
        const extra_relations = if (extended) @import("air/blake3_execution_profile.zig").Extension(@TypeOf(capture.*)).draw_count / 2 else 0;
        const parent_child = @TypeOf(capture.*) == ParentVerified;
        const proof = if (parent_child) &capture.capture else &capture.proof;
        const config = if (parent_child) try admitted.config() else admitted.config;
        const self = try a.create(State);
        errdefer a.destroy(self);
        self.allocator = a;
        self.composition = if (parent_child) try @import("air/blake3_parent_composition.zig").prepare(a, admitted, capture) else try @import("air/blake3_execution_composition.zig").prepare(a, admitted, capture, expected);
        errdefer self.composition.deinit();
        profile.lap("composition");
        self.deep = if (parent_child) try @import("air/blake3_parent_deep.zig").prepare(a, admitted, capture) else try @import("air/blake3_execution_deep.zig").prepare(a, admitted, capture, expected);
        errdefer self.deep.deinit();
        profile.lap("deep");
        self.fri = try @import("air/blake3_native_fri.zig").prepareCaptured(a, proof, config, &self.deep, 1502, 1504);
        errdefer self.fri.deinit();
        profile.lap("fri");
        var planned = if (parent_child) try @import("air/blake3_parent_transcript.zig").planReplay(a, admitted, capture, capacity) else try @import("air/blake3_execution_transcript.zig").planReplay(a, admitted, capture, expected, capacity);
        profile.lap("transcript_plan");
        errdefer planned.deinit();
        self.payloads = try @import("air/blake3_execution_payloads.zig").prepare(a, &self.composition, &planned, &self.deep, 1500, 1502, 5_000_012);
        errdefer self.payloads.deinit();
        profile.lap("payloads");
        self.challenges = try @import("air/blake3_execution_challenges.zig").prepareForRelations(@import("air/universal_challenges.zig").RELATION_COUNT + extra_relations, a, &self.composition, &planned, &self.deep, &self.fri, .{ 1500, 1502, 1504 }, 5_000_003);
        errdefer self.challenges.deinit();
        profile.lap("challenges");
        self.terminal = try @import("air/blake3_native_terminal_encoding.zig").prepare(a, &planned, &self.fri, 1504);
        errdefer self.terminal.deinit();
        profile.lap("terminal");
        self.queries = try @import("air/blake3_native_queries.zig").prepare(a, &planned, &self.deep, &self.fri);
        errdefer self.queries.deinit();
        profile.lap("queries");
        self.roots = if (parent_child) try @import("air/blake3_execution_roots.zig").prepareParent(a, admitted, capture, &planned) else try @import("air/blake3_execution_roots.zig").prepare(a, admitted, capture, expected, &planned);
        errdefer self.roots.deinit();
        profile.lap("roots");
        const layout = try @import("blake3_native_hash_layout.zig").Layout.init(a, try planned.hashCounts(), proof);
        self.context = .{ .child_key_id = expected, .child_config = config, .graph_ids = .{ self.composition.circuit.identity_digest, self.deep.graph.graph().identity_digest, self.fri.graph.graph().identity_digest }, .transcript_plan_id = planned.plan.id };
        if (parent_child) {
            self.context.statement_identity = admitted.key.context.statement_identity;
            self.context.span_binding_id = admitted.key.context.span_binding_id;
        }
        return .{ .state = self, .transcript = planned, .layout = layout, .proof = proof };
    }
    pub fn sources(self: *const State) source_mod.Sources {
        return .{ .composition = &self.composition, .transcript = &self.transcript, .deep = &self.deep, .fri = &self.fri, .payloads = &self.payloads, .challenges = &self.challenges, .terminal = &self.terminal, .queries = &self.queries, .openings = &self.openings, .roots = &self.roots, .paths = &self.paths };
    }
    /// Column ownership moves only after the complete row assembly succeeds.
    pub fn finish(self: *State) !Prepared {
        return .{ .rows = try rows_mod.prepareWithHashColumns(self.sources(), &self.hash_columns), .context = self.context };
    }
    pub fn deinit(self: *State) void {
        self.openings.deinit();
        self.paths.deinit();
        self.transcript.deinit();
        self.hash_columns.deinit();
        self.deinitPlanning();
    }
    fn deinitPlanning(self: *State) void {
        self.roots.deinit();
        self.queries.deinit();
        self.terminal.deinit();
        self.challenges.deinit();
        self.payloads.deinit();
        self.fri.deinit();
        self.deep.deinit();
        self.composition.deinit();
        self.allocator.destroy(self);
    }
};

/// Owns authenticated planning state while the capture remains borrowed.
/// Emission consumes this owner on success or error; deinit is idempotent.
/// Separating these phases lets an aggregate learn both layouts before emission.
pub const Planned = struct {
    state: ?*State,
    transcript: ?@import("air/blake3_native_transcript.zig").Planned,
    layout: @import("blake3_native_hash_layout.zig").Layout,
    proof: *const core.verifier.ProofCapture(@import("blake3_engine_protocol.zig").Hasher),
    pub fn deinit(self: *Planned) void {
        if (self.transcript) |*transcript| transcript.deinit();
        if (self.state) |state| state.deinitPlanning();
        self.transcript = null;
        self.state = null;
    }
    pub fn emit(owner: *Planned) !*State {
        const self = owner.state orelse return error.ConsumedParentPlan;
        defer owner.deinit();
        const a = self.allocator;
        const layout = owner.layout;
        const proof = owner.proof;
        const planned = if (owner.transcript) |*value| value else return error.ConsumedParentPlan;
        var profile = PreparationProfile.init();
        self.hash_columns = try @import("blake3_native_hash_columns.zig").Owner.init(a, layout);
        errdefer self.hash_columns.deinit();
        profile.lap("hash_columns");
        self.transcript = try planned.emitMainColumns(a, try self.hash_columns.transcript());
        owner.transcript = null;
        errdefer self.transcript.deinit();
        profile.lap("transcript");
        self.paths = try @import("air/blake3_stark_paths.zig").prepareMainColumns(a, proof, &self.deep.graph, &self.fri.graph, &self.queries.links, try self.hash_columns.paths());
        errdefer self.paths.deinit();
        profile.lap("paths");
        try layout.validateEmitted(.{ .g = self.transcript.live.hash_metadata.?.g_rows.len, .xor = self.transcript.live.hash_metadata.?.xor_rows.len }, .{ .g = self.paths.hash_metadata.?.g_rows.len, .xor = self.paths.hash_metadata.?.xor_rows.len });
        try @import("air/blake3_native_queries.zig").applyPathReads(a, &self.queries, &self.deep, self.paths.inputs.projection.bit_reads);
        profile.lap("path_reads");
        self.openings = try @import("air/blake3_native_openings.zig").prepare(a, &self.paths, &self.deep, &self.fri);
        errdefer self.openings.deinit();
        profile.lap("openings");
        if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_FUSION_CENSUS")) try rows_mod.fusionCensus(a, self.sources());
        owner.state = null;
        return self;
    }
};
