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
    arena: std.heap.ArenaAllocator,
    operations: []t.Operation,
    claim_payloads: []recorder.Payload,
    plan: plan_mod.Plan,
    live: t.Prepared,
    end: suite.Channel,
    pub fn deinit(self: *Prepared) void {
        self.live.deinit();
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub const Planned = struct {
    arena: std.heap.ArenaAllocator,
    operations: []t.Operation,
    claim_payloads: []recorder.Payload,
    plan: plan_mod.Plan,
    end: suite.Channel,
    pub fn deinit(self: *Planned) void {
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
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
        var live = if (columns) |out| try self.plan.prepareMainColumns(a, self.operations, out) else try self.plan.prepare(a, self.operations);
        errdefer live.deinit();
        if (!std.mem.eql(u8, &self.end.digestBytes(), &live.final_digest.?) or self.end.n_draws != live.next_draw) return error.InvalidNativeBlake3Transcript;
        const result = Prepared{ .arena = self.arena, .operations = self.operations, .claim_payloads = self.claim_payloads, .plan = self.plan, .live = live, .end = self.end };
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
    return finishInternal(backing, arena, r, capture, config, capacity);
}
/// Explicit PAGE specialization. It never widens legacy protocol selection.
pub fn finishReplayForCommitments(comptime count: usize, backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32) !Planned {
    comptime if (count != 10) @compileError("explicit PAGE transcript requires ten commitments");
    if (capture.commitments.len != count) return error.InvalidNativeBlake3Transcript;
    return finishInternal(backing, arena, r, capture, config, capacity);
}
/// Original commitment order: composition is the last commitment; first FRI
/// follows it. Exposed for exact slot fixtures without constructing a proof.
pub fn suffixRootSlots(commitments: usize) !struct { composition: t.Caller, fri: t.Caller } {
    if (commitments != 4 and commitments != 5 and commitments != 10) return error.InvalidNativeBlake3Transcript;
    return .{ .composition = try roots.caller(commitments - 1), .fri = try roots.caller(commitments) };
}
fn finishInternal(backing: std.mem.Allocator, arena: *std.heap.ArenaAllocator, r: *recorder.Recorder, capture: anytype, config: core.pcs.PcsConfig, capacity: u32) !Planned {
    if (capture.fri.layers.len == 0 or r.root_count != capture.commitments.len - 1) return error.InvalidNativeBlake3Transcript;
    const suffix_roots = try suffixRootSlots(capture.commitments.len);
    const a = arena.allocator();
    const lifting = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    const suffix_start = r.operations.items.len;
    _ = try pcs.appendStarkVerifierFrom(a, &r.operations, &r.native, capture, config, lifting, .{ .export_challenges = true, .export_queries = true, .composition_root = suffix_roots.composition, .fri_roots = suffix_roots.fri, .nonce = .{ .circuit = 4_100_001, .first_wire = 2 }, .sampled_values = SAMPLE_SOURCE, .terminal_coefficients = TERMINAL_SOURCE });
    // Prefix encoder temporaries are already owned. Own suffix capture slices too.
    for (r.operations.items[suffix_start..]) |*op| switch (op.*) {
        .routed_felts => |*v| v.values = try a.dupe(core.fields.qm31.QM31, v.values),
        .felts => |*v| v.* = try a.dupe(core.fields.qm31.QM31, v.*),
        else => {},
    };
    var plan = try plan_mod.Plan.initCompact(backing, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
    errdefer plan.deinit();
    if (std.posix.getenv("STWO_RISCV_PARENT_PREPARATION_PROFILE") != null) {
        const counts = plan.fixed.hashCounts();
        const metadata = @import("blake3_hash_metadata.zig");
        const full_bytes = try std.math.add(usize, try std.math.mul(usize, counts.g, @sizeOf(t.g.Row)), try std.math.mul(usize, counts.xor, @sizeOf(t.xor.Row)));
        const compact_bytes = try std.math.add(usize, try std.math.mul(usize, counts.g, @sizeOf(metadata.Row(t.g))), try std.math.mul(usize, counts.xor, @sizeOf(metadata.Row(t.xor))));
        std.debug.print("BLAKE3_TRUSTED_TRANSCRIPT_STORAGE g_rows={d} xor_rows={d} prior_full_bytes={d} compact_bytes={d} removed_bytes={d}\n", .{ counts.g, counts.xor, full_bytes, compact_bytes, full_bytes - compact_bytes });
    }
    const operations = try r.operations.toOwnedSlice(a);
    const claim_payloads = try r.payloads.toOwnedSlice(a);
    return .{ .arena = arena.*, .operations = operations, .claim_payloads = claim_payloads, .plan = plan, .end = r.native };
}
