//! Original private interaction/composition/FRI roots and PoW. Fixed/main and
//! optional witness commitments are externally supplied by the admitted bus.
const std = @import("std");
const Roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig").Prepared, capture: *const @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig").VerifiedCapture, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !@import("blake3_execution_roots.zig").Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const prefix = admitted.tree_count - 1;
    var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == Roots.CIRCUIT and receipt.source.first_wire >= prefix * 8) try filtered.append(arena.allocator(), receipt);
    var pcs = transcript.*;
    pcs.plan.fixed.root_reads = filtered.items;
    var result = try @import("blake3_execution_roots.zig").prepareCapturedExternal(a, &capture.proof, admitted.binding.first_roots[0], admitted.config, &pcs, prefix);
    result.external_key = true;
    result.external_main = true;
    return result;
}
