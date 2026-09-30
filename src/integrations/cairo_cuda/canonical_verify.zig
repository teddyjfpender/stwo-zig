//! Independent host replay before publishing a resident canonical Cairo proof.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const verifier = cairo.witness.resident_verifier;
const source = @import("canonical_source.zig");
const terminal = @import("executor/terminal_decode.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Decoded = struct {
    proof: verifier.Proof,
    claimed_sums: []QM31,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        allocator.free(self.claimed_sums);
        self.* = undefined;
    }
};

pub fn verifyAndDecode(allocator: std.mem.Allocator, prepared: *const source.Prepared, output: terminal.CanonicalProof) !Decoded {
    return verifyAndDecodeWithOptionalCapture(allocator, prepared, output, null);
}

/// The recursive leaf path retains authenticated openings in transcript
/// order. The ordinary publication path avoids that extra host allocation.
pub fn verifyAndDecodeWithCapture(
    allocator: std.mem.Allocator,
    prepared: *const source.Prepared,
    output: terminal.CanonicalProof,
    capture: *verifier.ProofCapture,
) !Decoded {
    return verifyAndDecodeWithOptionalCapture(allocator, prepared, output, capture);
}

fn verifyAndDecodeWithOptionalCapture(
    allocator: std.mem.Allocator,
    prepared: *const source.Prepared,
    output: terminal.CanonicalProof,
    capture: ?*verifier.ProofCapture,
) !Decoded {
    if (!std.meta.eql(prepared.protocol, output.protocol)) return error.CanonicalProofProtocolMismatch;
    const p = prepared.protocol;
    const geometry = verifier.ProtocolGeometry{
        .trace_tree_count = p.commitment_count,
        .fri_layer_count = p.fri_tree_count,
        .max_log_degree_bound = p.max_log_degree_bound,
        .query_pow_bits = p.query_pow_bits,
        .interaction_pow_bits = p.interaction_pow_bits,
        .log_blowup_factor = p.log_blowup_factor,
        .query_count = p.query_count,
        .log_last_layer_degree_bound = p.log_last_layer_degree_bound,
        .fold_step = p.fri_fold_step,
        .lifting_log_size = p.fri_lifting_log_size,
        .m31_channel = p.channel_profile == .blake2s_m31,
        .include_all_preprocessed_columns = p.include_all_preprocessed_columns,
    };
    const shape = try cairo.witness.resident_geometry.sampleShapeWithPolicy(allocator, prepared.composition, .{ p.trace_columns[0], p.trace_columns[1], p.trace_columns[2] }, p.include_all_preprocessed_columns);
    defer verifier.freeSampleShape(allocator, shape);
    const preprocessed_logs = try allocator.dupe(u32, prepared.preprocessed_logs);
    defer allocator.free(preprocessed_logs);
    const main_logs = try allocator.alloc(u32, p.trace_columns[1]);
    defer allocator.free(main_logs);
    const interaction_logs = try allocator.alloc(u32, p.trace_columns[2]);
    defer allocator.free(interaction_logs);
    const tree_logs = [3][]u32{ preprocessed_logs, main_logs, interaction_logs };
    for (prepared.composition.components) |component| for (component.trace_spans) |span| {
        if (span.tree == 1 or span.tree == 2) @memset(tree_logs[span.tree][span.start..span.end], component.trace_log_size);
    };
    const roots = output.words[output.structural.layout.commitments.start..output.structural.layout.commitments.end];
    if (roots.len != 32) return error.InvalidCanonicalRootGeometry;
    var transcript: [11]verifier.TranscriptInput = undefined;
    for (@import("executor/transcript/schedule.zig").bootstrap_mix_ordinals, &transcript) |ordinal, *binding| {
        binding.* = .{ .ordinal = ordinal, .words = switch (ordinal) {
            3 => roots[0..8],
            20 => roots[8..16],
            else => prepared.request.statement_bootstrap.words(ordinal) orelse return error.InvalidCanonicalStatement,
        } };
    }
    const verify_input: verifier.VerifyInput = .{
        .bundle = output.structural,
        .composition = prepared.composition,
        .tree_logs = tree_logs,
        .transcript_inputs = &transcript,
        .statement = &prepared.input,
    };
    if (capture) |out|
        try verifier.verifyRuntimeWithProofCapture(allocator, verify_input, geometry, out)
    else
        try verifier.verifyRuntime(allocator, verify_input, geometry);
    var proof = try verifier.decodeProofWithGeometry(allocator, output.structural, .{ .trees = shape }, geometry);
    errdefer proof.deinit(allocator);
    const sums = try allocator.alloc(QM31, prepared.composition.components.len);
    errdefer allocator.free(sums);
    const words = output.words[output.structural.layout.interaction_claim.start..output.structural.layout.interaction_claim.end];
    if (words.len != sums.len * 4) return error.InvalidCanonicalInteractionGeometry;
    for (sums, 0..) |*sum, index| sum.* = try cairo.witness.resident_types.qm31FromWords(words[index * 4 ..][0..4]);
    return .{ .proof = proof, .claimed_sums = sums };
}
