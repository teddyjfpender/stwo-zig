//! First roots are external public providers, including both PCS absorption reads.
const std = @import("std");
const roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_native_lookup_recursive_admission_v1.zig").Prepared, capture: *const @import("../../prover/block_v5_native_lookup_recursive_capture_v1.zig").VerifiedCapture, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !@import("blake3_execution_roots.zig").Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == roots.CIRCUIT and receipt.source.first_wire >= 16) try filtered.append(arena.allocator(), receipt);
    var pcs = transcript.*;
    pcs.plan.fixed.root_reads = filtered.items;
    var result = try @import("blake3_execution_roots.zig").prepareCaptured(a, &capture.proof, admitted.roots[0], admitted.config, &pcs, true);
    result.external_key = true;
    result.external_main = true;
    return result;
}
