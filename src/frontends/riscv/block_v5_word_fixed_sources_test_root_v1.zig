test {
    _ = @import("prover/block_v5_word_fixed_sources_test_v1.zig");
}
test "word fixed sources: actual typed native and original default parent bodies retained" {
    const std = @import("std");
    inline for (.{ @import("recursion/air/block_v5_word_recursive_shape_composition_v1.zig").Family.ram_lanes, .range16 }) |family| {
        const Family = @import("recursion/block_v5_word_recursive_fixed_sources_v1.zig").ForFamily(family);
        std.mem.doNotOptimizeAway(&Family.derive);
        std.mem.doNotOptimizeAway(&Family.validateAgainst);
        const Roster = @import("recursion/block_v5_word_recursive_fixed_roster_v1.zig").ForFamily(family);
        inline for (.{ &Roster.Owned.derive, &Roster.Owned.validateAgainst, &Roster.Owned.validateLive, &Roster.Owned.deinit, &Roster.ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKey }) |body| std.mem.doNotOptimizeAway(body);
    }
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_recursive_parent_fixed_sources_v1.zig").Owned.init);
    // The shared append recipe also retains the actual original default API.
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_recursive_parent_fixed_roster_v1.zig").Owned.init);
}
