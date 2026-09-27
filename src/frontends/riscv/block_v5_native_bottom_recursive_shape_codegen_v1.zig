//! Retains real fixed-only factories and original live adapters; never invokes.
const std = @import("std");
const Ram = @import("recursion/block_v5_ram_lanes_recursive_shape_v1.zig");
const Range = @import("recursion/block_v5_range16_recursive_shape_v1.zig");
const Page = @import("recursion/block_v5_memory_source_page_recursive_shape_v1.zig");
pub export fn stwo_native_bottom_recursive_shape_body_gate() void {
    inline for (.{ Ram, Range }) |Family| {
        inline for (.{ &Family.Owned.derive, &Family.Owned.validateAgainst, &Family.Owned.deinit, &Family.Shape.init, &Family.Shape.validateAgainst, &Family.Shape.deinit }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ .raw, .fold }) |kind| {
        const P = Page.ForKind(kind);
        const Fixed = @import("recursion/block_v5_memory_source_page_recursive_fixed_v1.zig").ForKind(kind);
        inline for (.{ &Fixed.Owned.derive, &Fixed.Owned.validateAgainst, &Fixed.Owned.deinit }) |body| std.mem.doNotOptimizeAway(body);
        inline for (.{ &P.Owned.derive, &P.Owned.validateAgainst, &P.Owned.geometryView, &P.Owned.deinit, &P.deriveLogs, &P.validateLogs }) |body| std.mem.doNotOptimizeAway(body);
    }
    // Exact unchanged live proof/capture factories are retained for compiler
    // parity, not called. Fixed-only setup creates no verifier authority.
    std.mem.doNotOptimizeAway(&@import("block_v5_memory_source_page_recursive_codegen_v1.zig").stwo_source_page_recursive_body_gate);
}
