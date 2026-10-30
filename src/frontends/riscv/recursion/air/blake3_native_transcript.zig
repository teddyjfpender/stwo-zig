//! Native V2 physical-lookup prefix joined to canonical BLAKE3 STARK/PCS replay.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("../blake3_engine_protocol.zig");
const statement_mod = @import("../../air/statement_v2.zig");
const claims_mod = @import("../../air/statement.zig");
const lookup = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const relations = @import("../../air/relation_challenges.zig");
const native = @import("../../proof_transcript.zig");
const t = @import("blake3_transcript_witness.zig");
const plan_mod = @import("blake3_transcript_plan.zig");
const recorder = @import("blake3_native_recorder.zig");
const pcs = @import("blake3_pcs_transcript.zig");
const roots = @import("blake3_root_sources.zig");
const native_verifier = @import("../../prover/verifier.zig");
pub const TERMINAL_SOURCE = t.Caller{ .circuit = 4_100_003, .first_wire = 0 };
pub const SAMPLE_SOURCE = t.Caller{ .circuit = 4_100_002, .first_wire = 0 };
pub const Prepared = struct {
    owns_plan: bool = true,
    arena: std.heap.ArenaAllocator,
    operations: []t.Operation,
    claim_payloads: []recorder.Payload,
    plan: plan_mod.Plan,
    live: t.Prepared,
    end: suite.Channel,
    pub fn deinit(self: *Prepared) void {
        self.live.deinit();
        if (self.owns_plan) self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
/// Live values for externally constrained exports. These are witness data, not
/// authority: the mixed parent must supply the original prefix and exact buses.
pub const ExternalDraw = struct { output: t.DrawOutput, values: [8]core.fields.m31.M31 };
pub const Planned = struct {
    /// False only for a verifier-owned compiler plan borrowed through emission.
    owns_plan: bool = true,
    external_draws: []const ExternalDraw = &.{},
    boundary: ?t.Boundary = null,
    arena: std.heap.ArenaAllocator,
    operations: []t.Operation,
    claim_payloads: []recorder.Payload,
    plan: plan_mod.Plan,
    end: suite.Channel,
    pub fn deinit(self: *Planned) void {
        if (self.owns_plan) self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validateExternalDraws(self: *const Planned) !void {
        const expected = if (self.boundary) |ports| ports.external_draw_outputs else &.{};
        if (expected.len != self.external_draws.len) return error.InvalidExecutionChallenge;
        for (expected, self.external_draws, 0..) |output, record, i| {
            if (!std.meta.eql(output, record.output)) return error.InvalidExecutionChallenge;
            for (expected[0..i]) |prior| if (std.meta.eql(prior, output)) return error.InvalidExecutionChallenge;
            var count: usize = 0;
            for (self.plan.fixed.draw_outputs) |actual| if (std.meta.eql(actual, output)) {
                count += 1;
            };
            if (count != 1) return error.InvalidExecutionChallenge;
        }
    }
    pub fn drawValues(self: *const Planned, output: t.DrawOutput) ![8]core.fields.m31.M31 {
        if (self.boundary) |ports| for (ports.external_draw_outputs, 0..) |external, i| {
            if (!std.meta.eql(external, output)) continue;
            if (i >= self.external_draws.len or !std.meta.eql(self.external_draws[i].output, output)) return error.InvalidExecutionChallenge;
            return self.external_draws[i].values;
        };
        if (output.operation >= self.operations.len or self.operations[output.operation] != .secure) return error.InvalidExecutionChallenge;
        const draw = self.operations[output.operation].secure;
        if (draw.output == null or !std.meta.eql(draw.output.?, output.role) or draw.consumption.words() != output.words) return error.InvalidExecutionChallenge;
        return draw.values;
    }
    pub fn hashCounts(self: *const Planned) !@import("blake3_draw_hash_layout.zig").Counts {
        try self.plan.validate();
        return self.plan.fixed.hashCounts();
    }
    /// Transfers planning ownership only on success; caller retains it on error.
    pub fn emit(self: *Planned, a: std.mem.Allocator) !Prepared {
        return self.emitWithColumns(a, null);
    }
    pub fn emitMainColumns(self: *Planned, a: std.mem.Allocator, columns: t.MainColumns) !Prepared {
        return self.emitWithColumns(a, columns);
    }
    fn emitWithColumns(self: *Planned, a: std.mem.Allocator, columns: ?t.MainColumns) !Prepared {
        var live = if (self.boundary) |ports|
            (if (columns) |out| try self.plan.prepareBoundaryMainColumns(a, self.operations, ports, out) else try self.plan.prepareBoundary(a, self.operations, ports))
        else if (columns) |out| try self.plan.prepareMainColumns(a, self.operations, out) else try self.plan.prepare(a, self.operations);
        errdefer live.deinit();
        if (!std.mem.eql(u8, &self.end.digestBytes(), &live.final_digest.?) or self.end.n_draws != live.next_draw) return error.InvalidNativeBlake3Transcript;
        const result = Prepared{ .owns_plan = self.owns_plan, .arena = self.arena, .operations = self.operations, .claim_payloads = self.claim_payloads, .plan = self.plan, .live = live, .end = self.end };
        self.* = undefined;
        return result;
    }
};
pub fn prepare(comptime Engine: type, backing: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claims_mod.RiscVInteractionClaim, capture: *const native_verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !Prepared {
    var planned = try planReplay(Engine, backing, statement, claim, capture, config, capacity);
    errdefer planned.deinit();
    return planned.emit(backing);
}
pub fn planReplay(comptime Engine: type, backing: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claims_mod.RiscVInteractionClaim, capture: *const native_verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !Planned {
    comptime {
        if (Engine.Hasher != suite.Hasher) @compileError("native adapter requires a BLAKE3 proof capture");
    }
    try capture.validate();
    try @import("../../prover/verifier_protocol.zig").V2Protocol.validate(statement);
    if (!std.meta.eql(statement.public_data.wireId(), capture.public_data.data.wireId()) or !std.meta.eql(statement.authority_id, capture.receipt.authority_id) or capture.proof.commitments.len != 4 or capture.proof.fri.layers.len == 0) return error.InvalidNativeBlake3Transcript;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var r = recorder.Recorder{ .a = a };
    config.mixInto(&r);
    try statement_mod.mixIntoNativeTranscript(&statement.public_data, &r);
    const manifest = lookup.Manifest.native();
    const admitted = try lookup.AuthenticatedStatement.init(&statement.core, &manifest);
    admitted.mixInto(&r);
    r.mixRoot(capture.proof.commitments[0]);
    r.mixRoot(capture.proof.commitments[1]);
    const challenges = native.verifyToRelations(a, &r, &statement.core, claim.interaction_pow) catch |err| {
        try r.check();
        return err;
    };
    var draws: [relations.DRAW_COUNT]core.fields.qm31.QM31 = undefined;
    try challenges.writeDraws(&draws);
    for (draws, capture.vm_air.relation_draws) |actual, expected| if (!actual.eql(expected)) return error.InvalidNativeBlake3Transcript;
    r.private_felts = true;
    try admitted.mixInteractionClaim(&r, &statement.core, &manifest, claim);
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count * 2 != relations.DRAW_COUNT or r.nonce_pending != null) return error.InvalidNativeBlake3Transcript;
    return finishReplay(backing, &arena, &r, &capture.proof, config, capacity);
}
/// Shared suffix/ownership boundary for native and full-width execution prefixes.
/// Transfers arena ownership only on success.
pub fn finishReplay(backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32) !Planned {
    if (capture.commitments.len != 4 and capture.commitments.len != 5) return error.InvalidNativeBlake3Transcript;
    return finishInternal(backing, arena, r, capture, config, capacity, null);
}
/// Explicit new-protocol specialization. Legacy selection remains four/five.
pub fn finishReplayForCommitments(comptime count: usize, backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32) !Planned {
    comptime if (count != 6 and count != 10) @compileError("explicit caller/PAGE transcript requires six/ten commitments");
    if (capture.commitments.len != count) return error.InvalidNativeBlake3Transcript;
    return finishInternal(backing, arena, r, capture, config, capacity, null);
}
/// Runtime count comes from an independently reconstructed union profile.
/// Existing native/caller/PAGE entry points retain their exact-count gates.
pub fn finishReplayForBoundedCommitments(backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32, commitments: usize) !Planned {
    if (commitments < 4 or commitments > 257 or capture.commitments.len != commitments) return error.InvalidNativeBlake3Transcript;
    return finishInternal(backing, arena, r, capture, config, capacity, null);
}
/// Same native channel replay, using independently compiled preprocessing.
/// The compiler must outlive Planned and emitted Prepared. Emission still
/// checks the exact fixed fingerprint against fresh request operations.
pub fn finishReplayForCommitmentsWithPlan(comptime count: usize, backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32, compiled: *const plan_mod.Plan) !Planned {
    comptime if (count != 6 and count != 10) @compileError("explicit caller/PAGE transcript requires six/ten commitments");
    if (capture.commitments.len != count) return error.InvalidNativeBlake3Transcript;
    return finishInternal(backing, arena, r, capture, config, capacity, compiled);
}
/// Original commitment order: composition is the last commitment; first FRI
/// follows it. Exposed for exact slot fixtures without constructing a proof.
pub const SuffixRootSlots = struct { composition: t.Caller, fri: t.Caller };
pub fn suffixRootSlots(commitments: usize) !SuffixRootSlots {
    if (commitments != 4 and commitments != 5 and commitments != 6 and commitments != 10) return error.InvalidNativeBlake3Transcript;
    return suffixRootSlotsBounded(commitments);
}
pub fn suffixRootSlotsBounded(commitments: usize) !SuffixRootSlots {
    if (commitments < 4 or commitments > 257) return error.InvalidNativeBlake3Transcript;
    return .{ .composition = try roots.caller(commitments - 1), .fri = try roots.caller(commitments) };
}
fn finishInternal(backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32, compiled: ?*const plan_mod.Plan) !Planned {
    if (capture.fri.layers.len == 0 or r.root_count != capture.commitments.len - 1) return error.InvalidNativeBlake3Transcript;
    // Public entry points select/validate the accepted commitment inventory.
    const composition_root = try roots.caller(capture.commitments.len - 1);
    const fri_root = try roots.caller(capture.commitments.len);
    const a = arena.allocator();
    const lifting = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    const suffix_start = r.operations.items.len;
    _ = try pcs.appendStarkVerifierFrom(a, &r.operations, &r.native, capture, config, lifting, .{ .export_challenges = true, .export_queries = true, .composition_root = composition_root, .fri_roots = fri_root, .nonce = .{ .circuit = 4_100_001, .first_wire = 2 }, .sampled_values = SAMPLE_SOURCE, .terminal_coefficients = TERMINAL_SOURCE });
    // Prefix encoder temporaries are already owned. Own suffix capture slices too.
    for (r.operations.items[suffix_start..]) |*op| switch (op.*) {
        .routed_felts => |*v| v.values = try a.dupe(core.fields.qm31.QM31, v.values),
        .felts => |*v| v.* = try a.dupe(core.fields.qm31.QM31, v.*),
        else => {},
    };
    var plan = if (compiled) |trusted| blk: {
        if (trusted.config.namespace != 1_000_000 or trusted.config.attempt_capacity != capacity) return error.CallerTranscriptCapacityMismatch;
        try trusted.validate();
        break :blk trusted.*;
    } else try plan_mod.Plan.initCompact(backing, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
    errdefer if (compiled == null) plan.deinit();
    if (std.posix.getenv("STWO_RISCV_PARENT_PREPARATION_PROFILE") != null) {
        const counts = plan.fixed.hashCounts();
        const metadata = @import("blake3_hash_metadata.zig");
        const full_bytes = try std.math.add(usize, try std.math.mul(usize, counts.g, @sizeOf(t.g.Row)), try std.math.mul(usize, counts.xor, @sizeOf(t.xor.Row)));
        const compact_bytes = try std.math.add(usize, try std.math.mul(usize, counts.g, @sizeOf(metadata.Row(t.g))), try std.math.mul(usize, counts.xor, @sizeOf(metadata.Row(t.xor))));
        std.debug.print("BLAKE3_TRUSTED_TRANSCRIPT_STORAGE g_rows={d} xor_rows={d} prior_full_bytes={d} compact_bytes={d} removed_bytes={d}\n", .{ counts.g, counts.xor, full_bytes, compact_bytes, full_bytes - compact_bytes });
    }
    const operations = try r.operations.toOwnedSlice(a);
    const claim_payloads = try r.payloads.toOwnedSlice(a);
    return .{ .owns_plan = compiled == null, .arena = arena.*, .operations = operations, .claim_payloads = claim_payloads, .plan = plan, .end = r.native };
}
