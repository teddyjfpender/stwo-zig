//! Public child metadata roots are supplied separately from PCS roots. The
//! child setup fixed root stays geometry-pinned; main/interaction roots remain
//! proved private transcript/path providers, preserving all Merkle equations.
const std = @import("std");
const shared = @import("blake3_execution_roots.zig");
const roots = @import("blake3_root_sources.zig");
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: *const @import("../blake3_native_parent_verifier.zig").Verified, transcript: *const @import("blake3_native_transcript.zig").Planned) !shared.Prepared {
    try capture.validate(admitted, admitted.expected_id);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == roots.CIRCUIT)
        try filtered.append(arena.allocator(), receipt);
    var pcs = transcript.*;
    pcs.plan.fixed.root_reads = filtered.items;
    return shared.prepareCaptured(a, &capture.capture, admitted.key.preprocessed_root, try admitted.config(), &pcs, false);
}
