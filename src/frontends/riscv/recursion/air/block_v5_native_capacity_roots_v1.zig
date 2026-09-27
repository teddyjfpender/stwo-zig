//! Both B5CT first roots are externally supplied. PCS roots/nonce preserve
//! their original authenticated transcript/path dataflow.
const std = @import("std");
const core = @import("stwo_core");
const admission = @import("../../prover/block_v5_native_capacity_recursive_admission_v1.zig");
const capture_mod = @import("../../prover/block_v5_native_capacity_proof_v1.zig");
const shared = @import("blake3_execution_roots.zig");
const roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const admission.Prepared, capture: *const capture_mod.VerifiedCapture, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !shared.Prepared {
    try capture.validate(admitted, expected);
    if (!admitted.reusable_public_inputs) return error.CapacityRecursivePublicInputsRequired;
    {
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
}
