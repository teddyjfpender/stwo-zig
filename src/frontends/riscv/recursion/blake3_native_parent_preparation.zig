//! One canonical verified-native-capture to BLAKE3 parent preparation path.
const std = @import("std");
const core = @import("stwo_core");
const statement_mod = @import("../air/statement_v2.zig");
const claim_mod = @import("../air/statement.zig");
const verifier = @import("../prover/verifier.zig");
const rows_mod = @import("air/blake3_native_parent_rows.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Prepared = struct {
    rows: rows_mod.Prepared,
    context: protocol.Context,
    allocation_budget: ?*SharedBudget = null,
    pub fn retainedBytes(self: Prepared) !usize {
        const payload = if (self.allocation_budget) |budget|
            try std.math.add(usize, budget.snapshot().live_bytes, @sizeOf(SharedBudget))
        else
            try self.rows.retainedBytes();
        return std.math.add(usize, @sizeOf(Prepared), payload);
    }
    pub fn deinit(self: *Prepared) void {
        self.rows.deinit();
        if (self.allocation_budget) |budget| budget.destroy();
        self.* = undefined;
    }
};
pub const Handoff = @import("owned_handoff.zig").Handoff(Prepared);

/// Prepares one item and transfers it to the bounded ready queue. The caller
/// reserves preparation/intermediate memory separately; send may block while
/// this producer still owns its prepared value. Failure destroys that value.
pub fn prepareAndSend(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32, host_byte_limit: usize, handoff: *Handoff) !void {
    var owned: ?Prepared = try prepareBounded(Engine, a, statement, claim, capture, config, capacity, host_byte_limit);
    defer if (owned) |*value| value.deinit();
    try handoff.send(&owned);
}

/// Enforces live allocation bytes for preparation intermediates and final rows.
/// Borrowed input captures, allocator overhead and thread stacks are separate.
pub fn prepareBounded(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32, host_byte_limit: usize) !Prepared {
    const budget = try SharedBudget.create(a, host_byte_limit);
    errdefer budget.destroy();
    var prepared = prepare(Engine, budget.allocator(), statement, claim, capture, config, capacity) catch |err| {
        if (err == error.OutOfMemory and budget.snapshot().exceeded) return error.PreparationHostBudgetExceeded;
        return err;
    };
    prepared.allocation_budget = budget;
    return prepared;
}

/// Normal entrypoint: all intermediates are released before returning owned rows.
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !Prepared {
    const state = try State.init(Engine, a, statement, claim, capture, config, capacity);
    defer state.deinit();
    return state.finish();
}
/// Diagnostic owner exposes the same preparation for source-mutation qualification.
/// Its stable address keeps every intermediate owner valid until deinit.
pub const State = struct {
    allocator: std.mem.Allocator,
    context: protocol.Context,
    prepared: @import("air/blake3_native_transcript.zig").Prepared,
    hash_layout: @import("blake3_native_hash_layout.zig").Layout,
    hash_columns: ?@import("blake3_native_hash_columns.zig").Owner = null,
    composition: @import("vm_air_composition_circuit.zig").Prepared,
    payloads: @import("air/blake3_native_payload_links.zig").Prepared,
    deep: @import("air/blake3_native_deep.zig").Prepared,
    shared_samples: @import("air/blake3_native_sample_links.zig").Prepared,
    fri: @import("air/blake3_native_fri.zig").Prepared,
    joined_challenges: @import("air/blake3_native_pcs_challenges.zig").Prepared,
    terminal_rows: @import("air/blake3_native_terminal_encoding.zig").Prepared,
    query_rows: @import("air/blake3_native_queries.zig").Prepared,
    paths: @import("air/blake3_stark_paths.zig").Prepared,
    opening_rows: @import("air/blake3_native_openings.zig").Prepared,
    root_words: @import("air/blake3_native_root_nonce.zig").Prepared,
    public_boundary: @import("air/blake3_native_public_boundary.zig").Prepared,
    public_join: @import("air/blake3_native_public_links.zig").Prepared,
    public_inputs: @import("air/blake3_native_public_sources.zig").Prepared,
    pub fn init(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !*State {
        return initMode(true, Engine, a, statement, claim, capture, config, capacity);
    }
    /// Diagnostic row-emission oracle; shares the complete preparation builder.
    pub fn initRowOracle(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !*State {
        return initMode(false, Engine, a, statement, claim, capture, config, capacity);
    }
    fn initMode(comptime final_columns: bool, comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !*State {
        const self = try a.create(State);
        errdefer a.destroy(self);
        self.allocator = a;
        self.hash_columns = null;
        errdefer if (self.hash_columns) |*columns| columns.deinit();
        self.prepared = blk: {
            var planned = try @import("air/blake3_native_transcript.zig").planReplay(Engine, a, statement, claim, capture, config, capacity);
            errdefer planned.deinit();
            self.hash_layout = try @import("blake3_native_hash_layout.zig").Layout.init(a, try planned.hashCounts(), &capture.proof);
            if (final_columns) {
                self.hash_columns = try @import("blake3_native_hash_columns.zig").Owner.init(a, self.hash_layout);
                break :blk try planned.emitMainColumns(a, try self.hash_columns.?.transcript());
            }
            break :blk try planned.emit(a);
        };
        errdefer self.prepared.deinit();
        self.composition = try @import("vm_air_composition_prepared_v2.zig").prepare(a, capture, config);
        errdefer self.composition.deinit();
        self.payloads = try @import("air/blake3_native_payload_links.zig").prepareColumns(a, &self.composition, &self.prepared, 1500);
        errdefer self.payloads.deinit();
        self.deep = try @import("air/blake3_native_deep.zig").prepare(Engine, a, capture, config);
        errdefer self.deep.deinit();
        self.shared_samples = try @import("air/blake3_native_sample_links.zig").prepareColumns(a, &self.composition, &self.payloads, &self.deep, 1500, 1502);
        errdefer self.shared_samples.deinit();
        self.fri = try @import("air/blake3_native_fri.zig").prepare(Engine, a, capture, config, &self.deep, 1502, 1504);
        errdefer self.fri.deinit();
        self.joined_challenges = try @import("air/blake3_native_pcs_challenges.zig").prepareColumns(a, &self.composition, &self.prepared, &self.deep, &self.fri, .{ 1500, 1502, 1504 });
        errdefer self.joined_challenges.deinit();
        self.terminal_rows = try @import("air/blake3_native_terminal_encoding.zig").prepareColumns(a, &self.prepared, &self.fri, 1504);
        errdefer self.terminal_rows.deinit();
        self.query_rows = try @import("air/blake3_native_queries.zig").prepare(a, &self.prepared, &self.deep, &self.fri);
        errdefer self.query_rows.deinit();
        self.paths = if (self.hash_columns) |*columns| try @import("air/blake3_stark_paths.zig").prepareMainColumns(a, &capture.proof, &self.deep.graph, &self.fri.graph, &self.query_rows.links, try columns.paths()) else try @import("air/blake3_stark_paths.zig").prepare(a, &capture.proof, &self.deep.graph, &self.fri.graph, &self.query_rows.links);
        errdefer self.paths.deinit();
        try self.hash_layout.validateEmitted(.{ .g = if (self.prepared.live.hash_metadata) |m| m.g_rows.len else self.prepared.live.g_rows.len, .xor = if (self.prepared.live.hash_metadata) |m| m.xor_rows.len else self.prepared.live.xor_rows.len }, .{ .g = if (self.paths.hash_metadata) |m| m.g_rows.len else self.paths.live.g_rows.len, .xor = if (self.paths.hash_metadata) |m| m.xor_rows.len else self.paths.live.xor_rows.len });
        try @import("air/blake3_native_queries.zig").applyPathReads(a, &self.query_rows, &self.deep, self.paths.inputs.projection.bit_reads);
        self.opening_rows = try @import("air/blake3_native_openings.zig").prepare(a, &self.paths, &self.deep, &self.fri);
        errdefer self.opening_rows.deinit();
        self.root_words = try @import("air/blake3_native_root_nonce.zig").prepare(Engine, a, statement, capture, config, claim.interaction_pow, &self.prepared);
        errdefer self.root_words.deinit();
        self.public_boundary = try @import("air/blake3_native_public_boundary.zig").prepare(Engine, a, capture);
        errdefer self.public_boundary.deinit();
        self.public_join = try @import("air/blake3_native_public_links.zig").prepare(a, &self.composition, &self.public_boundary, &self.joined_challenges, &self.payloads);
        errdefer self.public_join.deinit();
        try self.payloads.releaseNodeMap();
        self.public_inputs = try @import("air/blake3_native_public_sources.zig").prepare(a, statement, config, &self.prepared, &self.public_boundary);
        errdefer self.public_inputs.deinit();
        self.context = protocol.Context.fromSources(statement, config, self.sources());
        return self;
    }
    pub fn deinit(self: *State) void {
        const a = self.allocator;
        self.public_inputs.deinit();
        self.public_join.deinit();
        self.public_boundary.deinit();
        self.root_words.deinit();
        self.opening_rows.deinit();
        self.paths.deinit();
        self.query_rows.deinit();
        self.terminal_rows.deinit();
        self.joined_challenges.deinit();
        self.fri.deinit();
        self.shared_samples.deinit();
        self.deep.deinit();
        self.payloads.deinit();
        self.composition.deinit();
        self.prepared.deinit();
        if (self.hash_columns) |*columns| columns.deinit();
        a.destroy(self);
    }
    pub fn finish(self: *State) !Prepared {
        return .{ .rows = if (self.hash_columns) |*columns| try rows_mod.prepareWithHashColumns(self.sources(), columns) else try rows_mod.prepare(self.allocator, self.sources()), .context = self.context };
    }
    pub fn sources(self: *const State) rows_mod.Sources {
        return .{
            .composition = &self.composition,
            .transcript = &self.prepared,
            .deep = &self.deep,
            .fri = &self.fri,
            .payloads = &self.payloads,
            .samples = &self.shared_samples,
            .challenges = &self.joined_challenges,
            .terminal = &self.terminal_rows,
            .queries = &self.query_rows,
            .paths = &self.paths,
            .openings = &self.opening_rows,
            .roots = &self.root_words,
            .public_boundary = &self.public_boundary,
            .public_join = &self.public_join,
            .public_inputs = &self.public_inputs,
        };
    }
};
