test {
    _ = @import("prover/block_v5_caller_recursive_admission_catalog_test_v1.zig");
    _ = @import("prover/block_v5_caller_recursive_pipeline_test_v1.zig");
}
test "caller admission ownership: actual assembled source admission and original borrowed staged producer bodies retained only" {
    const std = @import("std");
    const Catalog = @import("prover/block_v5_caller_recursive_admission_catalog_v1.zig").Catalog;
    inline for (.{ &Catalog.init, &Catalog.initFromBounds, &Catalog.get, &Catalog.deinit }) |body| std.mem.doNotOptimizeAway(body);
    @import("block_v5_caller_recursive_pipeline_codegen.zig").stwo_caller_recursive_pipeline_body_gate();
}
