test {
    _ = @import("prover/block_v5_word_fixed_transcript_test_v1.zig");
}
test "word fixed transcript: actual original policy derivation and live replay bodies are retained only" {
    const std = @import("std");
    const Fixed = @import("recursion/block_v5_word_recursive_fixed_transcript_v1.zig");
    inline for (.{ @import("recursion/air/block_v5_word_transcript_prefix_v1.zig").Family.ram_lanes, .range16 }) |family| {
        const Owner = Fixed.ForFamily(family).Owned;
        inline for (.{ &Owner.derive, &Owner.validateAgainst, &Owner.deinit, &Fixed.ForFamily(family).recordForShape }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ &@import("recursion/air/block_v5_ram_lanes_transcript_v1.zig").prefix, &@import("recursion/air/block_v5_ram_lanes_transcript_v1.zig").planReplay, &@import("recursion/air/block_v5_range16_transcript_v1.zig").prefix, &@import("recursion/air/block_v5_range16_transcript_v1.zig").planReplay }) |body| std.mem.doNotOptimizeAway(body);
}
