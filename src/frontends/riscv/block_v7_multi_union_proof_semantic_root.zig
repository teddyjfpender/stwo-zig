test "force multi union original proof lifecycle" {
    @import("std").mem.doNotOptimizeAway(&@import("prover/block_v7_multi_union_proof_v1.zig").prove);
    @import("std").mem.doNotOptimizeAway(&@import("prover/block_v7_multi_union_proof_v1.zig").verify);
}
