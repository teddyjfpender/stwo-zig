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
pub fn prepare(comptime Engine: type, backing: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, claim: *const claims_mod.RiscVInteractionClaim, capture: *const native_verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, capacity: u32) !Prepared {
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
    const lifting = capture.proof.fri.layers[0].path_depth + capture.proof.fri.layers[0].fold_step;
    const suffix_start = r.operations.items.len;
    _ = try pcs.appendStarkVerifierFrom(a, &r.operations, &r.native, &capture.proof, config, lifting, .{ .export_challenges = true, .export_queries = true, .composition_root = try roots.caller(3), .fri_roots = try roots.caller(4), .nonce = .{ .circuit = 4_100_001, .first_wire = 2 }, .sampled_values = .{ .circuit = 4_100_002, .first_wire = 0 }, .terminal_coefficients = .{ .circuit = 4_100_003, .first_wire = 0 } });
    // Prefix encoder temporaries are already owned. Own suffix capture slices too.
    for (r.operations.items[suffix_start..]) |*op| switch (op.*) {
        .routed_felts => |*v| v.values = try a.dupe(core.fields.qm31.QM31, v.values),
        .felts => |*v| v.* = try a.dupe(core.fields.qm31.QM31, v.*),
        else => {},
    };
    var plan = try plan_mod.Plan.init(backing, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
    errdefer plan.deinit();
    var live = try plan.prepare(backing, r.operations.items);
    errdefer live.deinit();
    if (!std.mem.eql(u8, &r.native.digestBytes(), &live.final_digest.?) or r.native.n_draws != live.next_draw) return error.InvalidNativeBlake3Transcript;
    return .{ .arena = arena, .operations = try r.operations.toOwnedSlice(a), .claim_payloads = try r.payloads.toOwnedSlice(a), .plan = plan, .live = live, .end = r.native };
}
