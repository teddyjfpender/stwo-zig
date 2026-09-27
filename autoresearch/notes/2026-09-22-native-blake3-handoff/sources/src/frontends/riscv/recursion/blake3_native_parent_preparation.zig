//! One canonical verified-native-capture to BLAKE3 parent preparation path.
const std = @import("std");
const core = @import("stwo_core");
const statement_mod = @import("../air/statement_v2.zig");
const claim_mod = @import("../air/statement.zig");
const verifier = @import("../prover/verifier.zig");
const rows_mod = @import("air/blake3_native_parent_rows.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
pub const Prepared = struct {
    rows: rows_mod.Prepared,
    context: protocol.Context,
    pub fn retainedBytes(self: Prepared) !usize {
        return std.math.add(usize, @sizeOf(Prepared), self.rows.arena.queryCapacity());
    }
    pub fn deinit(self: *Prepared) void {
        self.rows.deinit();
        self.* = undefined;
    }
};
pub const Handoff = @import("owned_handoff.zig").Handoff(Prepared);

/// Prepares one item and transfers it to the bounded ready queue. The caller
/// reserves preparation/intermediate memory separately; send may block while
/// this producer still owns its prepared value. Failure destroys that value.
pub fn prepareAndSend(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32, handoff: *Handoff) !void {
    var owned: ?Prepared = try prepare(Engine, a, statement, claim, capture, config, capacity);
    defer if (owned) |*value| value.deinit();
    try handoff.send(&owned);
}

/// Normal entrypoint: all intermediates are released before returning owned rows.
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claim_mod.RiscVInteractionClaim, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !Prepared {
    const state = try State.init(Engine, a, statement, claim, capture, config, capacity);
    defer state.deinit();
    return state.finish(a);
}
/// Diagnostic owner exposes the same preparation for source-mutation qualification.
/// Its stable address keeps every intermediate owner valid until deinit.
pub const State = struct {
    allocator: std.mem.Allocator,
    context: protocol.Context,
    prepared: @import("air/blake3_native_transcript.zig").Prepared,
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
        const self = try a.create(State);
        errdefer a.destroy(self);
        self.allocator = a;
        self.prepared = try @import("air/blake3_native_transcript.zig").prepare(Engine, a, statement, claim, capture, config, capacity);
        errdefer self.prepared.deinit();
        self.composition = try @import("vm_air_composition_prepared_v2.zig").prepare(a, capture, config);
        errdefer self.composition.deinit();
        self.payloads = try @import("air/blake3_native_payload_links.zig").prepare(a, &self.composition, &self.prepared, 1500);
        errdefer self.payloads.deinit();
        self.deep = try @import("air/blake3_native_deep.zig").prepare(Engine, a, capture, config);
        errdefer self.deep.deinit();
        self.shared_samples = try @import("air/blake3_native_sample_links.zig").prepare(a, &self.composition, &self.payloads, &self.deep, 1500, 1502);
        errdefer self.shared_samples.deinit();
        self.fri = try @import("air/blake3_native_fri.zig").prepare(Engine, a, capture, config, &self.deep, 1502, 1504);
        errdefer self.fri.deinit();
        self.joined_challenges = try @import("air/blake3_native_pcs_challenges.zig").prepare(a, &self.composition, &self.prepared, &self.deep, &self.fri, .{ 1500, 1502, 1504 });
        errdefer self.joined_challenges.deinit();
        self.terminal_rows = try @import("air/blake3_native_terminal_encoding.zig").prepare(a, &self.prepared, &self.fri, 1504);
        errdefer self.terminal_rows.deinit();
        self.query_rows = try @import("air/blake3_native_queries.zig").prepare(a, &self.prepared, &self.deep, &self.fri);
        errdefer self.query_rows.deinit();
        self.paths = try @import("air/blake3_stark_paths.zig").prepare(a, &capture.proof, &self.deep.graph, &self.fri.graph, &self.query_rows.links);
        errdefer self.paths.deinit();
        try @import("air/blake3_native_queries.zig").applyPathReads(a, &self.query_rows, &self.deep, self.paths.inputs.projection.bit_reads);
        self.opening_rows = try @import("air/blake3_native_openings.zig").prepare(a, &self.paths, &self.deep, &self.fri);
        errdefer self.opening_rows.deinit();
        self.root_words = try @import("air/blake3_native_root_nonce.zig").prepare(Engine, a, statement, capture, config, claim.interaction_pow, &self.prepared);
        errdefer self.root_words.deinit();
        self.public_boundary = try @import("air/blake3_native_public_boundary.zig").prepare(Engine, a, capture);
        errdefer self.public_boundary.deinit();
        self.public_join = try @import("air/blake3_native_public_links.zig").prepare(a, &self.composition, &self.public_boundary, &self.joined_challenges, &self.payloads);
        errdefer self.public_join.deinit();
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
        a.destroy(self);
    }
    pub fn finish(self: *const State, a: std.mem.Allocator) !Prepared {
        return .{ .rows = try rows_mod.prepare(a, self.sources()), .context = self.context };
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
