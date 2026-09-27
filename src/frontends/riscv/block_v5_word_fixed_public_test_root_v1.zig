test {
    _ = @import("prover/block_v5_word_fixed_public_test_v1.zig");
}
test "word fixed public: actual independent native owners and original live supplier bodies retained" {
    const std = @import("std");
    inline for (.{ @import("recursion/air/block_v5_word_public_schedule_v1.zig").Family.ram_lanes, .range16 }) |family| {
        const Owner = @import("recursion/block_v5_word_recursive_fixed_public_v1.zig").ForFamily(family).Owned;
        inline for (.{ &Owner.derive, &Owner.validateAgainst, &Owner.deinit }) |body| std.mem.doNotOptimizeAway(body);
    }
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_range16_recursive_public_bus_v1.zig").prepare);
}
