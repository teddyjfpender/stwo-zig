//! Eight independently supplied PAGE roots and original private interaction,
//! composition, FRI roots and PoW nonce at their exact commitment indices.
const std = @import("std");
const Shared = @import("blake3_execution_roots.zig");
const Roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, transcript: *const @import("blake3_native_transcript.zig").Planned) !Shared.Prepared {
    _ = comptime @import("block_v5_memory_source_page_transcript_v1.zig").kindOf(@TypeOf(capture.*));
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == Roots.CIRCUIT and receipt.source.first_wire >= 64) try filtered.append(arena.allocator(), receipt);
    var suffix = transcript.*;
    suffix.plan.fixed.root_reads = filtered.items;
    var result = try Shared.prepareCapturedExternalFor(10, a, &capture.proof, admitted.pin.roots[0], admitted.config, &suffix, 8);
    result.external_key = true;
    result.external_main = true;
    return result;
}
