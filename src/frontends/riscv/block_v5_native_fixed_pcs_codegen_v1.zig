//! Retained actual factories only: no commit/proof/capture invocation.
const std = @import("std");
const Fixed = @import("recursion/block_v5_native_recursive_fixed_pcs_v1.zig");
const Profiles = @import("recursion/block_v5_native_fixed_pcs_profile_v1.zig");
pub export fn stwo_native_fixed_pcs_body_gate() void {
    inline for (.{ @import("recursion/air/block_v5_word_recursive_shape_composition_v1.zig").Family.ram_lanes, .range16 }) |family| {
        const Family = Fixed.ForWord(family);
        inline for (.{ &Family.derive, &Family.validateAgainst, &Family.Owned.deinit, &Profiles.ForWord(family).derive, &Profiles.ForWord(family).validate }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ .raw, .fold }) |kind| {
        const Family = Fixed.ForPage(kind);
        inline for (.{ &Family.compileFromRouting, &Family.Owned.deinit, &Family.requireComplete, &Profiles.ForPage(kind).derive, &Profiles.ForPage(kind).validate }) |body| std.mem.doNotOptimizeAway(body);
    }
    // Exact original public signatures/default parent bodies are also emitted.
    inline for (.{ &@import("recursion/air/blake3_stark_paths.zig").compileFixedShape, &@import("recursion/air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig").Owned.init, &@import("recursion/air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig").Owned.validateAgainst, &@import("recursion/air/block_v5_recursive_parent_fixed_openings_v1.zig").Owned.init }) |body| std.mem.doNotOptimizeAway(body);
}
