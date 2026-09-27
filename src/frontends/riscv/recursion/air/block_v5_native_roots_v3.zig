//! Pin both B5SS first roots in the recursive fixed key, while the remaining
//! PCS roots and nonce retain their proved transcript/path dataflow.
const std = @import("std");
const core = @import("stwo_core");
const admission = @import("../../prover/block_v5_native_recursive_admission_v3.zig");
const capture_mod = @import("../../prover/block_v5_native_execution_proof_v3.zig");
const shared = @import("blake3_execution_roots.zig");
const roots = @import("blake3_root_sources.zig");
const boundary = @import("blake3_boundary.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const admission.Prepared, capture: *const capture_mod.VerifiedCapture, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !shared.Prepared {
    try capture.validate(admitted, expected);
    if (admitted.reusable_public_inputs) {
        // Shared PCS root/nonce ownership stays unchanged. Strip only the
        // additional public transcript receipts before using its PCS adapter.
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
        for (transcript.plan.fixed.root_reads) |receipt|
            if (receipt.source.circuit == roots.CIRCUIT) try filtered.append(arena.allocator(), receipt);
        var pcs = transcript.*;
        pcs.plan.fixed.root_reads = filtered.items;
        var result = try shared.prepareCaptured(a, &capture.proof, admitted.template.fixed_root, admitted.config, &pcs, false);
        errdefer result.deinit();
        // Both first roots come exclusively from the versioned external public
        // supply. No fixed or private provider may duplicate their tuples.
        if (result.wordCount() < 8) return error.InvalidExecutionRoots;
        result.external_key = true;
        try result.skipFirstWords(8);
        return result;
    }
    var result = try shared.prepareCaptured(a, &capture.proof, admitted.template.fixed_root, admitted.config, transcript, false);
    errdefer result.deinit();
    if (result.wordCount() < 8 or transcript.plan.fixed.root_reads.len < 2) return error.InvalidExecutionRoots;
    const receipt = transcript.plan.fixed.root_reads[1];
    const source = try roots.caller(1);
    if (!std.meta.eql(receipt.source, source)) return error.InvalidExecutionRoots;
    const paths = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidExecutionRoots;
    var main: [8]boundary.Row = undefined;
    for (&main, receipt.uses, 0..) |*row, reads, coordinate| {
        const uses = try std.math.add(u32, reads, paths);
        if (uses >= core.fields.m31.Modulus) return error.InvalidExecutionRoots;
        row.* = try boundary.logicalRow(source.circuit, source.first_wire + @as(u32, @intCast(coordinate)), core.fields.m31.M31.fromCanonical(uses), std.mem.readInt(u32, capture.proof.commitments[1][coordinate * 4 ..][0..4], .little));
    }
    try result.attachMain(a, main);
    try result.skipFirstWords(8);
    return result;
}
