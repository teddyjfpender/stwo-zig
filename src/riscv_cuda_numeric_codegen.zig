//! Linux object-only gate; performs no CUDA execution and links no GPU runtime.
const X = @import("integrations/riscv_cuda/hybrid_quotient_executor_v1.zig");
const std = @import("std");
export fn stwo_riscv_cuda_numeric_codegen() void {
    inline for (.{ &X.Owner.open, &X.Owner.deinit, &X.Owner.executor }) |f| std.mem.doNotOptimizeAway(f);
    const Callback = @import("stwo_prover_engine").pcs.QuotientExecutor;
    var owner: X.Owner = undefined;
    const callback: Callback = owner.executor();
    std.mem.doNotOptimizeAway(callback.run);
}
