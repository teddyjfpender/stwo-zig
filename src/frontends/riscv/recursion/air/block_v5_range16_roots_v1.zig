//! Both initial PCS roots are external public policy; their Merkle path reads
//! still close against actual independently supplied root coordinates.
const std = @import("std");
const roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !@import("blake3_execution_roots.zig").Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == roots.CIRCUIT) try filtered.append(arena.allocator(), receipt);
    var pcs = transcript.*;
    pcs.plan.fixed.root_reads = filtered.items;
    var result = try @import("blake3_execution_roots.zig").prepareCaptured(a, &capture.proof, admitted.roots[0], admitted.config, &pcs, true);
    result.external_key = true;
    result.external_main = true;
    return result;
}
